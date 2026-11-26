//! Durable maintenance journal outside all product directories. The stable
//! machine lock serializes every writer. An intent is persisted *before* each
//! creation, and cleanup only touches resources named by this installation.
use super::HostLayout;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    InstallDir,
    StateDir,
    RunDir,
    CoreDir,
    SocketDir,
    HostImage,
    Group,
    Data,
    Registration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Installing,
    Installed,
    Disabled,
    Reclaimed,
    Unregistered,
    IpcRemoved,
    GroupRemoved,
    StateRemoved,
    InstallRemoved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    install_id: String,
    phase: Phase,
    planned: Vec<Resource>,
    completed: Vec<Resource>,
    group_gid: Option<u32>,
    #[serde(default)]
    deferred: Option<DeferredOutcome>,
    /// Stage of an uncommitted `etd-host upgrade`. Omitted when there is
    /// none, so a host build without upgrade still reads the journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upgrade: Option<UpgradeStage>,
}

/// Durable stages of `etd-host upgrade`, written before the step they name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStage {
    /// About to stop and disable the service; nothing replaced yet.
    Disabling,
    /// Swapping the image, kernels and registration; backups exist.
    Replacing,
    /// The payload is verified and in place; the new host is starting. It
    /// clears the stage itself once it serves, which commits the upgrade.
    Starting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeferredOutcome {
    Pending { pid: u32 },
    Failed { error: String },
}

pub struct LifecycleJournal {
    path: PathBuf,
    record: Record,
}
impl LifecycleJournal {
    fn path(layout: &HostLayout) -> PathBuf {
        layout.maintenance.join("lifecycle.json")
    }
    pub fn open(layout: &HostLayout) -> io::Result<Option<Self>> {
        Self::read(Self::path(layout))
    }
    fn read(path: PathBuf) -> io::Result<Option<Self>> {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let record: Record = serde_json::from_reader(file).map_err(io::Error::other)?;
        Ok(Some(Self { path, record }))
    }
    pub fn begin(layout: &HostLayout) -> io::Result<Self> {
        Self::new_at(Self::path(layout))
    }
    fn new_at(path: PathBuf) -> io::Result<Self> {
        if path.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "maintenance journal already exists",
            ));
        }
        let journal = Self {
            path,
            record: Record {
                install_id: uuid::Uuid::new_v4().to_string(),
                phase: Phase::Installing,
                planned: vec![],
                completed: vec![],
                group_gid: None,
                deferred: None,
                upgrade: None,
            },
        };
        journal.save()?;
        Ok(journal)
    }
    pub fn phase(&self) -> Phase {
        self.record.phase
    }
    pub fn install_id(&self) -> &str {
        &self.record.install_id
    }
    /// A deferred helper is fenced to the specific install transaction and
    /// the final cleanup phase. It may never stop/reclaim a later install.
    pub fn can_finish_deferred(&self, install_id: &str) -> bool {
        self.record.install_id == install_id
            && matches!(self.phase(), Phase::StateRemoved | Phase::InstallRemoved)
    }
    pub fn deferred(&self) -> Option<&DeferredOutcome> {
        self.record.deferred.as_ref()
    }
    pub fn set_deferred(&mut self, outcome: DeferredOutcome) -> io::Result<()> {
        if !self.can_finish_deferred(self.install_id()) {
            return Err(io::Error::other(
                "deferred outcome outside final uninstall phase",
            ));
        }
        self.record.deferred = Some(outcome);
        self.save()
    }
    pub fn planned(&self, resource: Resource) -> bool {
        self.record.planned.contains(&resource)
    }
    pub fn group_gid(&self) -> Option<u32> {
        self.record.group_gid
    }
    pub fn set_group_gid(&mut self, gid: u32) -> io::Result<()> {
        self.record.group_gid = Some(gid);
        self.save()
    }
    pub fn plan(&mut self, resource: Resource) -> io::Result<()> {
        if !self.planned(resource) {
            self.record.planned.push(resource);
            if let Err(error) = self.save() {
                self.record.planned.pop();
                return Err(error);
            }
        }
        Ok(())
    }
    pub fn complete(&mut self, resource: Resource) -> io::Result<()> {
        if !self.planned(resource) {
            return Err(io::Error::other("unplanned install resource"));
        }
        if !self.record.completed.contains(&resource) {
            self.record.completed.push(resource);
            self.save()?;
        }
        Ok(())
    }
    pub fn create(
        &mut self,
        resource: Resource,
        action: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.plan(resource)?;
        if let Err(error) = action() {
            // Collision means the atomic create did not establish ownership.
            if error.kind() == io::ErrorKind::AlreadyExists {
                self.record.planned.retain(|planned| *planned != resource);
                self.save()?;
            }
            return Err(error);
        }
        self.complete(resource)
    }
    pub fn rollback_resources(&self) -> Vec<Resource> {
        [
            Resource::Registration,
            Resource::SocketDir,
            Resource::Group,
            Resource::StateDir,
            Resource::InstallDir,
        ]
        .into_iter()
        .filter(|resource| self.planned(*resource))
        .collect()
    }
    pub fn advance(&mut self, phase: Phase) -> io::Result<()> {
        if phase < self.record.phase {
            return Err(io::Error::other("maintenance phase cannot go backwards"));
        }
        self.record.phase = phase;
        self.save()
    }
    pub fn upgrade_stage(&self) -> Option<UpgradeStage> {
        self.record.upgrade
    }
    /// Record an upgrade stage (only on an installed service), or `None`
    /// once the upgrade is committed or rolled back.
    pub fn set_upgrade_stage(&mut self, stage: Option<UpgradeStage>) -> io::Result<()> {
        if stage.is_some() && self.record.phase != Phase::Installed {
            return Err(io::Error::other(
                "only an installed service can be upgraded",
            ));
        }
        if self.record.upgrade != stage {
            let previous = std::mem::replace(&mut self.record.upgrade, stage);
            if let Err(error) = self.save() {
                self.record.upgrade = previous;
                return Err(error);
            }
        }
        Ok(())
    }
    pub fn resume_service(&mut self) -> io::Result<()> {
        if self.record.phase != Phase::Disabled {
            return Err(io::Error::other(
                "service can only resume before reclaim has completed",
            ));
        }
        self.record.phase = Phase::Installed;
        self.save()
    }
    /// Retrying a completed stage performs no action; retrying an incomplete
    /// stage invokes its idempotent operation again.
    pub fn step(
        &mut self,
        phase: Phase,
        action: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.phase() >= phase {
            return Ok(());
        }
        action()?;
        self.advance(phase)
    }
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => sync_parent(&self.path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn save(&self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("journal has no parent"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut file, &self.record).map_err(io::Error::other)?;
        file.flush()?;
        file.as_file().sync_all()?;
        // Windows scanners can briefly hold either name without delete
        // sharing. Retry only the atomic replacement of the same synced file;
        // never delete the old journal or fall back to an in-place write.
        #[cfg(windows)]
        {
            let mut attempts = 0;
            loop {
                match file.persist(&self.path) {
                    Ok(_) => break,
                    Err(error)
                        if matches!(error.error.raw_os_error(), Some(5 | 32 | 33))
                            && attempts < 20 =>
                    {
                        file = error.file;
                        attempts += 1;
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(error) => return Err(error.error),
                }
            }
        }
        #[cfg(unix)]
        file.persist(&self.path).map_err(|error| error.error)?;
        sync_parent(&self.path)
    }
}
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("journal has no parent"))?,
    )?
    .sync_all()?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_creation_failure_preserves_intent_for_rollback_and_reinstall() {
        let resources = [
            Resource::InstallDir,
            Resource::StateDir,
            Resource::RunDir,
            Resource::CoreDir,
            Resource::SocketDir,
            Resource::HostImage,
            Resource::Group,
            Resource::Data,
            Resource::Registration,
        ];
        for failed in 0..resources.len() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("journal");
            let mut journal = LifecycleJournal::new_at(path.clone()).unwrap();
            let mut existing = Vec::new();
            for (index, resource) in resources.iter().copied().enumerate() {
                let result = journal.create(resource, || {
                    existing.push(resource);
                    if index == failed {
                        Err(io::Error::other("injected after creation"))
                    } else {
                        Ok(())
                    }
                });
                if index == failed {
                    assert_eq!(result.unwrap_err().to_string(), "injected after creation");
                    break;
                }
                result.unwrap();
            }
            let journal = LifecycleJournal::read(path.clone()).unwrap().unwrap();
            assert_eq!(journal.phase(), Phase::Installing);
            for resource in journal.rollback_resources() {
                existing.retain(|r| match resource {
                    Resource::InstallDir => !matches!(
                        r,
                        Resource::InstallDir | Resource::CoreDir | Resource::HostImage
                    ),
                    Resource::StateDir => {
                        !matches!(r, Resource::StateDir | Resource::RunDir | Resource::Data)
                    }
                    _ => *r != resource,
                });
            }
            assert!(existing.is_empty());
            journal.clear().unwrap();
            assert!(LifecycleJournal::new_at(path).is_ok());
        }
    }
    #[test]
    fn collision_is_not_owned_by_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal");
        let mut journal = LifecycleJournal::new_at(path.clone()).unwrap();
        assert!(
            journal
                .create(Resource::InstallDir, || Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "foreign path"
                )))
                .is_err()
        );
        let journal = LifecycleJournal::read(path).unwrap().unwrap();
        assert!(journal.rollback_resources().is_empty());
    }
    #[test]
    fn delayed_helper_cannot_act_on_other_installations_or_earlier_phases() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal");
        let mut old = LifecycleJournal::new_at(path.clone()).unwrap();
        let id = old.install_id().to_owned();
        old.advance(Phase::Installed).unwrap();
        assert!(!old.can_finish_deferred(&id));
        old.advance(Phase::StateRemoved).unwrap();
        assert!(old.can_finish_deferred(&id));
        old.clear().unwrap();
        let mut new = LifecycleJournal::new_at(path).unwrap();
        new.advance(Phase::StateRemoved).unwrap();
        assert!(!new.can_finish_deferred(&id));
    }
    #[test]
    fn upgrade_stage_is_durable_and_invisible_when_clear() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal");
        let mut journal = LifecycleJournal::new_at(path.clone()).unwrap();
        assert!(
            journal
                .set_upgrade_stage(Some(UpgradeStage::Disabling))
                .is_err(),
            "not installed yet"
        );
        journal.advance(Phase::Installed).unwrap();
        let clear = fs::read_to_string(&path).unwrap();
        assert!(!clear.contains("upgrade"), "{clear}");
        for stage in [
            UpgradeStage::Disabling,
            UpgradeStage::Replacing,
            UpgradeStage::Starting,
        ] {
            journal.set_upgrade_stage(Some(stage)).unwrap();
            journal = LifecycleJournal::read(path.clone()).unwrap().unwrap();
            assert_eq!(journal.upgrade_stage(), Some(stage));
        }
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("\"upgrade\":\"starting\"")
        );
        journal.set_upgrade_stage(None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), clear);
        // A journal written before upgrade existed still reads.
        let old = clear.replace(",\"deferred\":null", "");
        fs::write(&path, old).unwrap();
        assert_eq!(
            LifecycleJournal::read(path)
                .unwrap()
                .unwrap()
                .upgrade_stage(),
            None
        );
    }
    #[test]
    fn every_uninstall_phase_can_retry_after_failure() {
        let phases = [
            Phase::Disabled,
            Phase::Reclaimed,
            Phase::Unregistered,
            Phase::IpcRemoved,
            Phase::GroupRemoved,
            Phase::StateRemoved,
            Phase::InstallRemoved,
        ];
        for failed in 0..phases.len() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("journal");
            let mut journal = LifecycleJournal::new_at(path.clone()).unwrap();
            journal.advance(Phase::Installed).unwrap();
            let mut removed = Vec::new();
            for (index, phase) in phases.iter().copied().enumerate() {
                let result = journal.step(phase, || {
                    if !removed.contains(&phase) {
                        removed.push(phase);
                    }
                    if index == failed {
                        Err(io::Error::other("injected"))
                    } else {
                        Ok(())
                    }
                });
                if index == failed {
                    assert_eq!(result.unwrap_err().to_string(), "injected");
                    break;
                }
                result.unwrap();
            }
            let mut journal = LifecycleJournal::read(path).unwrap().unwrap();
            for (index, phase) in phases.iter().copied().enumerate() {
                journal
                    .step(phase, || {
                        assert!(index >= failed);
                        if !removed.contains(&phase) {
                            removed.push(phase);
                        }
                        Ok(())
                    })
                    .unwrap();
            }
            assert_eq!(journal.phase(), Phase::InstallRemoved);
            assert_eq!(removed, phases);
            journal.clear().unwrap();
        }
    }
}
