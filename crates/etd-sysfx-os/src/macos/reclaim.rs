use super::{observation, observe::MacObserver, pf};
use async_trait::async_trait;
use etd_sysfx::*;
use futures_util::future::BoxFuture;
use std::sync::Arc;

pub(super) struct MacReclaimer {
    pub(super) kind: EffectKind,
    pub(super) observer: Arc<MacObserver>,
    pub(super) cores: Arc<super::holders::CoreIdentity>,
}

fn concrete(effect: &Effect) -> &ObjectKey {
    effect
        .observation
        .as_ref()
        .and_then(|o| o.key.as_ref())
        .unwrap_or(&effect.key)
}

#[async_trait]
impl Reclaimer for MacReclaimer {
    fn kind(&self) -> EffectKind {
        self.kind
    }
    fn rank(&self) -> u8 {
        self.kind.default_rank()
    }
    async fn probe(&self, e: &Effect) -> Probe {
        if e.kind != self.kind {
            return Probe::Indeterminate("wrong effect kind".into());
        }
        match self.observer.observe(self.kind, concrete(e)).await {
            Ok(Some(observed)) => Probe::Present(observed),
            Ok(None) => Probe::Absent,
            Err(err) => Probe::Indeterminate(err.to_string()),
        }
    }
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        if self.kind != e.kind || e.undo != Undo::EnsureAbsent {
            return Err(ReclaimError::Unsupported(e.kind));
        }
        let current = match self.probe(e).await {
            Probe::Absent => return Ok(Reclaimed::AlreadyAbsent),
            Probe::Indeterminate(err) => return Err(ReclaimError::Indeterminate(err)),
            Probe::Present(o) => o,
        };
        let expected = e.observation.as_ref().and_then(|o| o.credential.as_ref());
        if expected.is_some() && current.credential.as_ref() != expected {
            return Err(ReclaimError::CredentialMismatch);
        }
        if self.kind == EffectKind::MacFenceRule {
            let key = concrete(e);
            let rule =
                pf::Rule::from_key(key).map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            if let EffectScope::Instance { instance, epoch } = &e.scope {
                let spec = FenceSpec {
                    instance: instance.clone(),
                    epoch: *epoch,
                    address: ([127, 0, 0, 1], rule.port).into(),
                };
                if pf::Rule::for_spec(&spec) != rule {
                    return Err(ReclaimError::CredentialMismatch);
                }
            }
            if e.key != *key
                || current.credential
                    != Some(Credential::ExclusiveContainer {
                        container: pf::ANCHOR.into(),
                    })
            {
                return Err(ReclaimError::CredentialMismatch);
            }
            let cores = self.cores.clone();
            let changed = tokio::task::spawn_blocking(move || pf::change(rule, false, &cores))
                .await
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            return Ok(if changed {
                Reclaimed::Removed
            } else {
                Reclaimed::AlreadyAbsent
            });
        }
        if expected.is_none() {
            return Err(ReclaimError::CredentialMismatch);
        }
        // Darwin tears down the utun and its routes after the last control
        // socket closes. Deleting a route by CIDR can hit an unrelated LAN.
        Err(ReclaimError::Busy(
            "waiting for macOS to release the utun and its routes".into(),
        ))
    }
}

pub(super) struct MacSweep;
impl Sweeper for MacSweep {
    fn find_marked<'a>(
        &'a self,
        _: Option<&'a InstallKey>,
        _: &'a [etd_contract::InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async {
            // User hosts have no privileged system effects of their own.
            if !nix::unistd::Uid::effective().is_root() {
                return Ok(vec![]);
            }
            let rules = tokio::task::spawn_blocking(pf::sweep_rules)
                .await
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?
                .map_err(|e| ReclaimError::Indeterminate(e.to_string()))?;
            Ok(rules
                .into_iter()
                .map(|rule| {
                    let key = rule.key();
                    FoundObject {
                        kind: EffectKind::MacFenceRule,
                        observation: observation(
                            &key,
                            Credential::ExclusiveContainer {
                                container: pf::ANCHOR.into(),
                            },
                        ),
                        key,
                        origin: FoundBy::ExclusiveContainer,
                    }
                })
                .collect())
        })
    }
}
