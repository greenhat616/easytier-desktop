//! The elevated session form's decisions (doc#13 #choose #sequence), with
//! scripted connectors, a scripted token and a scripted starter: which host
//! is used, when exactly one start happens, how cancelled prompts and early
//! exits are reported, and that nothing starts without `ensure`.
use async_trait::async_trait;
use etd_app::launcher_session::{
    CleanupError, ElevatedSessionConfig, ElevationStarter, HostChoice, HostChoiceFile,
    RECLAIM_ALL_USERS_ARGS, RECLAIM_ARGS, SESSION_HOST_ARGS, SessionParts, StartError,
    StartedProcess, UiElevation, reclaim_session_leftovers, refusal_of,
};
use etd_app::launcher_user::{
    ConnectorFactory, HostSpawner, LauncherTimings, LocalHostLauncher, ServiceHostConfig,
    SpawnedHost, UserHostConfig,
};
use etd_app::{HostLauncher, LaunchError, LaunchFailure, LaunchFailureKind, SessionRefusal};
use etd_contract::HostMode;
use etd_ipc::{
    BoxConn, Connector, Endpoint, OsUserId, PeerIdentity, ServerExpectation, ServerIdentity,
    ServerRequirement,
};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Answer {
    Verified,
    Absent,
    Impostor,
    /// `ERROR_PIPE_BUSY`: something holds the pipe.
    Busy,
    /// Never answers within the connect limit.
    Hangs,
}

/// What the started session host does.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Start {
    Listens,
    StaysSilent,
    Exits(u32),
    Cancelled,
    Fails,
}

/// One start: how (consent or direct), program, arguments.
type StartRecord = (&'static str, PathBuf, Vec<String>);

#[derive(Clone)]
struct World {
    answers: Arc<Mutex<HashMap<Endpoint, Answer>>>,
    elevation: Arc<Mutex<UiElevation>>,
    start: Arc<Mutex<Start>>,
    /// Every start: how, program, arguments.
    starts: Arc<Mutex<Vec<StartRecord>>>,
    user_spawns: Arc<Mutex<u32>>,
    /// While set, a start waits: the UAC prompt is open.
    prompt_open: Arc<(Mutex<bool>, Condvar)>,
}

impl World {
    fn new(elevation: UiElevation, start: Start) -> Self {
        Self {
            answers: Arc::default(),
            elevation: Arc::new(Mutex::new(elevation)),
            start: Arc::new(Mutex::new(start)),
            starts: Arc::default(),
            user_spawns: Arc::default(),
            prompt_open: Arc::default(),
        }
    }
    /// Starts wait until [`World::answer_prompt`].
    fn hold_prompt(&self) {
        *self.prompt_open.0.lock().unwrap() = true;
    }
    fn answer_prompt(&self) {
        *self.prompt_open.0.lock().unwrap() = false;
        self.prompt_open.1.notify_all();
    }
    /// Waits until `n` starts were made.
    async fn starts_reach(&self, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.starts().len() < n {
            assert!(std::time::Instant::now() < deadline, "no start");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    fn answer(&self, endpoint: &Endpoint, answer: Answer) {
        self.answers
            .lock()
            .unwrap()
            .insert(endpoint.clone(), answer);
    }
    fn starts(&self) -> Vec<StartRecord> {
        self.starts.lock().unwrap().clone()
    }
    fn started(
        &self,
        how: &'static str,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError> {
        self.starts.lock().unwrap().push((
            how,
            program.to_path_buf(),
            args.iter().map(|a| (*a).to_owned()).collect(),
        ));
        let (open, answered) = &*self.prompt_open;
        drop(
            answered
                .wait_while(open.lock().unwrap(), |open| *open)
                .unwrap(),
        );
        match *self.start.lock().unwrap() {
            Start::Listens => {
                self.answer(&session_pipe(), Answer::Verified);
                Ok(Box::new(Process(None)))
            }
            Start::StaysSilent => Ok(Box::new(Process(None))),
            Start::Exits(code) => Ok(Box::new(Process(Some(code)))),
            Start::Cancelled => Err(StartError::Cancelled),
            Start::Fails => Err(StartError::Failed(io::Error::other("cannot start"))),
        }
    }
}

struct Process(Option<u32>);

impl StartedProcess for Process {
    fn exit_code(&mut self) -> io::Result<Option<u32>> {
        Ok(self.0)
    }
}

impl ElevationStarter for World {
    fn elevation(&self) -> io::Result<UiElevation> {
        Ok(*self.elevation.lock().unwrap())
    }
    fn start_with_consent(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError> {
        self.started("consent", program, args)
    }
    fn start_direct(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError> {
        self.started("direct", program, args)
    }
}

struct FakeConnector(World);

#[async_trait]
impl Connector for FakeConnector {
    async fn connect(&self, endpoint: &Endpoint) -> io::Result<(BoxConn, ServerIdentity)> {
        let answer = *self
            .0
            .answers
            .lock()
            .unwrap()
            .get(endpoint)
            .unwrap_or(&Answer::Absent);
        match answer {
            Answer::Absent => Err(io::Error::from_raw_os_error(2)),
            Answer::Busy => Err(io::Error::from_raw_os_error(231)),
            Answer::Hangs => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Err(io::ErrorKind::NotFound.into())
            }
            Answer::Impostor => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the server token is not elevated",
            )),
            Answer::Verified => {
                let (client, _server) = tokio::io::duplex(8);
                let identity = ServerIdentity {
                    peer: PeerIdentity {
                        user: OsUserId::WindowsSid("S-1-5-21-1".into()),
                        groups: Vec::new(),
                        pid: 1,
                        session: Some(1),
                        elevated: true,
                    },
                    exe: PathBuf::from("etd-host.exe"),
                };
                Ok((Box::new(client), identity))
            }
        }
    }
}

impl ConnectorFactory for World {
    fn connector(&self, _: &ServerExpectation) -> Arc<dyn Connector> {
        Arc::new(FakeConnector(self.clone()))
    }
}

impl HostSpawner for World {
    fn spawn(&self, _: &UserHostConfig) -> io::Result<Box<dyn SpawnedHost>> {
        *self.user_spawns.lock().unwrap() += 1;
        Err(io::ErrorKind::Unsupported.into())
    }
}

fn pipe(name: &str) -> Endpoint {
    Endpoint::NamedPipe(name.into())
}

fn session_pipe() -> Endpoint {
    pipe("session")
}

fn program() -> PathBuf {
    PathBuf::from(r"C:\Program Files\EasyTier Desktop\etd-host.exe")
}

fn session_config() -> ElevatedSessionConfig {
    ElevatedSessionConfig {
        program: program(),
        endpoint: session_pipe(),
        expectation: ServerExpectation {
            exe_dir: r"C:\Program Files\EasyTier Desktop".into(),
            requirement: ServerRequirement::CurrentUserElevated,
        },
    }
}

/// `installed` decides whether the service's program file exists.
fn service_config(installed: bool) -> ServiceHostConfig {
    let program = if installed {
        std::env::current_exe().unwrap()
    } else {
        PathBuf::from("definitely/not/installed/etd-host")
    };
    let mut config = ServiceHostConfig::standard(program);
    config.endpoint = pipe("service");
    config
}

fn launcher(world: &World, service_installed: bool) -> LocalHostLauncher {
    launcher_with(world, service_installed, false, None)
}

/// `user`: also offer a user host on `pipe("user")`; `choice`: the saved
/// first-run choice.
fn launcher_with(
    world: &World,
    service_installed: bool,
    user: bool,
    choice: Option<HostChoiceFile>,
) -> LocalHostLauncher {
    let user = user.then(|| UserHostConfig {
        program: "etd-host".into(),
        args: Vec::new(),
        endpoint: pipe("user"),
        expectation: ServerExpectation {
            exe_dir: "dir".into(),
            requirement: ServerRequirement::CurrentUser,
        },
    });
    LocalHostLauncher::with_parts(
        Some(service_config(service_installed)),
        user,
        Arc::new(world.clone()),
        Arc::new(world.clone()),
        LauncherTimings {
            startup: Duration::from_millis(80),
            poll: Duration::from_millis(5),
            connect: Duration::from_millis(50),
        },
    )
    .with_session(SessionParts {
        config: session_config(),
        starter: Arc::new(world.clone()),
        choice,
    })
}

fn session_args() -> Vec<String> {
    SESSION_HOST_ARGS.iter().map(|a| (*a).to_owned()).collect()
}

#[tokio::test]
async fn a_registered_service_is_used_and_no_session_host_is_started() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    world.answer(&pipe("service"), Answer::Verified);
    let target = launcher(&world, true)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap();
    assert_eq!(target.mode, HostMode::Service);
    // Installed but not running: still the service (start or repair it),
    // never a session host beside it.
    let world = World::new(UiElevation::Limited, Start::Listens);
    let result = launcher(&world, true)
        .ensure(HostMode::ElevatedSession)
        .await;
    assert!(matches!(result, Err(LaunchError::Timeout)), "{result:?}");
    assert!(world.starts().is_empty());
}

#[tokio::test]
async fn a_running_session_host_is_reused_without_a_prompt() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    world.answer(&session_pipe(), Answer::Verified);
    let target = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap();
    assert_eq!(target.mode, HostMode::ElevatedSession);
    assert_eq!(
        target.expectation.requirement,
        ServerRequirement::CurrentUserElevated
    );
    assert!(world.starts().is_empty());
}

#[tokio::test]
async fn a_split_token_admin_gets_exactly_one_prompt() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    let launcher = Arc::new(launcher(&world, false));
    let (first, second) = tokio::join!(
        launcher.ensure(HostMode::ElevatedSession),
        launcher.ensure(HostMode::ElevatedSession)
    );
    assert_eq!(first.unwrap().mode, HostMode::ElevatedSession);
    assert_eq!(second.unwrap().mode, HostMode::ElevatedSession);
    assert_eq!(world.starts(), [("consent", program(), session_args())]);
}

#[tokio::test]
async fn an_elevated_ui_starts_the_host_directly() {
    let world = World::new(UiElevation::Elevated, Start::Listens);
    launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap();
    assert_eq!(world.starts(), [("direct", program(), session_args())]);
}

#[tokio::test]
async fn a_standard_account_is_sent_to_the_service() {
    let world = World::new(UiElevation::Standard, Start::Listens);
    let result = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await;
    assert!(matches!(
        result,
        Err(LaunchError::Unsupported(HostMode::ElevatedSession))
    ));
    assert!(world.starts().is_empty());
    let failure = LaunchFailure::new(Some(HostMode::ElevatedSession), &result.unwrap_err());
    assert!(failure.guidance().unwrap().contains("system service"));
}

#[tokio::test]
async fn a_cancelled_prompt_is_elevation_denied() {
    let world = World::new(UiElevation::Limited, Start::Cancelled);
    let error = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap_err();
    assert!(matches!(error, LaunchError::ElevationDenied));
    let failure = LaunchFailure::new(Some(HostMode::ElevatedSession), &error);
    assert_eq!(failure.kind, LaunchFailureKind::ElevationDenied);
    assert!(failure.guidance().unwrap().contains("Connect"));
}

#[tokio::test]
async fn a_failed_start_is_a_spawn_error() {
    let world = World::new(UiElevation::Limited, Start::Fails);
    let error = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap_err();
    assert!(matches!(error, LaunchError::Spawn(_)), "{error:?}");
}

#[tokio::test]
async fn each_early_exit_is_reported_as_its_refusal() {
    let cases = [
        (3, LaunchFailureKind::ServiceInstalled),
        (4, LaunchFailureKind::SessionDirectory),
        (5, LaunchFailureKind::OtherUsersLeftovers),
        (6, LaunchFailureKind::EndpointOccupied),
    ];
    for (code, kind) in cases {
        let world = World::new(UiElevation::Limited, Start::Exits(code));
        let error = launcher(&world, false)
            .ensure(HostMode::ElevatedSession)
            .await
            .unwrap_err();
        assert!(matches!(error, LaunchError::SessionRefused(_)), "{error:?}");
        let failure = LaunchFailure::new(Some(HostMode::ElevatedSession), &error);
        assert_eq!(failure.kind, kind, "exit code {code}");
        assert!(failure.guidance().is_some());
    }
    let world = World::new(UiElevation::Limited, Start::Exits(1));
    let error = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, LaunchError::Spawn(text) if text.contains("exit code 1")),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_impostor_on_the_session_pipe_is_never_used() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    world.answer(&session_pipe(), Answer::Impostor);
    let error = launcher(&world, false)
        .ensure(HostMode::ElevatedSession)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        LaunchError::SessionRefused(SessionRefusal::EndpointOccupied)
    ));
    assert!(world.starts().is_empty());
}

#[tokio::test]
async fn a_slow_host_times_out_and_is_not_started_twice() {
    let world = World::new(UiElevation::Limited, Start::StaysSilent);
    let launcher = launcher(&world, false);
    assert!(matches!(
        launcher.ensure(HostMode::ElevatedSession).await,
        Err(LaunchError::Timeout)
    ));
    // Still running: the next Connect waits for it, no second prompt.
    assert!(matches!(
        launcher.ensure(HostMode::ElevatedSession).await,
        Err(LaunchError::Timeout)
    ));
    assert_eq!(world.starts().len(), 1);
}

#[tokio::test]
async fn probing_finds_a_running_session_host_and_never_starts_one() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    let launcher = launcher(&world, false);
    assert_eq!(launcher.probe().await.unwrap(), None);
    world.answer(&session_pipe(), Answer::Verified);
    assert_eq!(
        launcher.probe().await.unwrap().unwrap().mode,
        HostMode::ElevatedSession
    );
    // The installed service comes first.
    world.answer(&pipe("service"), Answer::Verified);
    assert_eq!(
        launcher.probe().await.unwrap().unwrap().mode,
        HostMode::Service
    );
    assert!(world.starts().is_empty());
}

#[test]
fn refusal_exit_codes_match_the_host() {
    assert_eq!(refusal_of(3), Some(SessionRefusal::ServiceInstalled));
    assert_eq!(refusal_of(4), Some(SessionRefusal::NotConforming));
    assert_eq!(refusal_of(5), Some(SessionRefusal::OtherUsersLeftovers));
    assert_eq!(refusal_of(6), Some(SessionRefusal::EndpointOccupied));
    for other in [0, 1, 2, 7, 101] {
        assert_eq!(refusal_of(other), None);
    }
}

#[test]
fn clean_up_runs_reclaim_elevated_and_reports_its_outcome() {
    let world = World::new(UiElevation::Limited, Start::Exits(0));
    reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)).unwrap();
    reclaim_session_leftovers(&world, &program(), true, Duration::from_secs(1)).unwrap();
    let starts = world.starts();
    assert_eq!(
        starts.iter().map(|(_, _, a)| a.clone()).collect::<Vec<_>>(),
        [
            RECLAIM_ARGS.map(str::to_owned).to_vec(),
            RECLAIM_ALL_USERS_ARGS.map(str::to_owned).to_vec()
        ]
    );
    assert!(starts.iter().all(|(how, _, _)| *how == "consent"));

    let world = World::new(UiElevation::Limited, Start::Cancelled);
    assert_eq!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)),
        Err(CleanupError::Declined)
    );
    let world = World::new(UiElevation::Elevated, Start::Exits(5));
    assert_eq!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)),
        Err(CleanupError::Refused(SessionRefusal::OtherUsersLeftovers))
    );
    let world = World::new(UiElevation::Elevated, Start::Exits(1));
    assert_eq!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)),
        Err(CleanupError::Exit(1))
    );
    let world = World::new(UiElevation::Elevated, Start::StaysSilent);
    assert_eq!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_millis(50)),
        Err(CleanupError::Timeout(Duration::from_millis(50)))
    );
}

/// The smoke test's step 4 (msg#2290): a failed clean-up said "The EasyTier
/// host did not start", the host-start guidance, which hid its exit code.
#[test]
fn a_failed_clean_up_says_what_failed_not_that_a_host_did_not_start() {
    let failures = [
        CleanupError::Declined,
        CleanupError::Unsupported,
        CleanupError::Start("not found".into()),
        CleanupError::Refused(SessionRefusal::ServiceInstalled),
        CleanupError::Refused(SessionRefusal::NotConforming),
        CleanupError::Refused(SessionRefusal::OtherUsersLeftovers),
        CleanupError::Exit(1),
        CleanupError::Timeout(Duration::from_secs(300)),
        CleanupError::Io("gone".into()),
    ];
    for failure in &failures {
        let text = failure.user_text();
        assert!(!text.contains("host did not start"), "{text}");
        assert!(!text.is_empty());
    }
    assert!(CleanupError::Exit(1).user_text().contains("exit code 1"));
    assert!(
        CleanupError::Exit(1)
            .user_text()
            .contains("etd-host reclaim --mode elevated-session")
    );
    assert!(
        CleanupError::Declined
            .user_text()
            .contains("Press Clean Up to be asked again")
    );
    assert_eq!(
        CleanupError::from(LaunchError::ElevationDenied),
        CleanupError::Declined
    );
    assert_eq!(
        CleanupError::from(LaunchError::Spawn("x".into())),
        CleanupError::Start("x".into())
    );
}

#[test]
fn the_host_choice_is_remembered() {
    let dir = tempfile::tempdir().unwrap();
    let file = HostChoiceFile::new(dir.path().join("nested").join("host-choice"));
    assert_eq!(file.load(), None);
    file.save(HostChoice::ElevatedSession).unwrap();
    assert_eq!(file.load(), Some(HostChoice::ElevatedSession));
    file.save(HostChoice::Service).unwrap();
    assert_eq!(file.load(), Some(HostChoice::Service));
    std::fs::write(dir.path().join("nested").join("host-choice"), "garbage").unwrap();
    assert_eq!(file.load(), None);
}

/// The bridge abandons a Connect when another Connect or a probe supersedes
/// it, but the consent call cannot be cancelled: the pending prompt stays
/// the one launch, and later calls get its outcome.
#[tokio::test]
async fn a_superseded_connect_keeps_the_pending_prompt() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    world.hold_prompt();
    let launcher = Arc::new(launcher(&world, false));
    let first = tokio::spawn({
        let launcher = launcher.clone();
        async move { launcher.ensure(HostMode::ElevatedSession).await }
    });
    world.starts_reach(1).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());

    let again = tokio::spawn({
        let launcher = launcher.clone();
        async move { launcher.ensure(HostMode::ElevatedSession).await }
    });
    let probe = tokio::spawn({
        let launcher = launcher.clone();
        async move { launcher.probe().await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !again.is_finished() && !probe.is_finished(),
        "they wait for the prompt"
    );
    world.answer_prompt();
    assert_eq!(
        again.await.unwrap().unwrap().mode,
        HostMode::ElevatedSession
    );
    assert_eq!(
        probe.await.unwrap().unwrap().unwrap().mode,
        HostMode::ElevatedSession
    );
    assert_eq!(world.starts().len(), 1, "exactly one prompt");
}

/// Nobody waits any more when the user accepts: the host it started is
/// still this launcher's, and the next Connect uses it without a prompt.
#[tokio::test]
async fn a_prompt_answered_after_everyone_left_still_counts() {
    let world = World::new(UiElevation::Limited, Start::Listens);
    world.hold_prompt();
    let launcher = Arc::new(launcher(&world, false));
    let first = tokio::spawn({
        let launcher = launcher.clone();
        async move { launcher.ensure(HostMode::ElevatedSession).await }
    });
    world.starts_reach(1).await;
    first.abort();
    world.answer_prompt();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        launcher
            .ensure(HostMode::ElevatedSession)
            .await
            .unwrap()
            .mode,
        HostMode::ElevatedSession
    );
    assert_eq!(world.starts().len(), 1);
}

#[tokio::test]
async fn concurrent_callers_share_one_denied_prompt() {
    let world = World::new(UiElevation::Limited, Start::Cancelled);
    world.hold_prompt();
    let launcher = Arc::new(launcher(&world, false));
    let ensure = || {
        let launcher = launcher.clone();
        tokio::spawn(async move { launcher.ensure(HostMode::ElevatedSession).await })
    };
    let (first, second) = (ensure(), ensure());
    world.starts_reach(1).await;
    let probe = tokio::spawn({
        let launcher = launcher.clone();
        async move { launcher.probe().await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    world.answer_prompt();
    for result in [first.await.unwrap(), second.await.unwrap()] {
        assert!(
            matches!(result, Err(LaunchError::ElevationDenied)),
            "{result:?}"
        );
    }
    assert!(matches!(
        probe.await.unwrap(),
        Err(LaunchError::ElevationDenied)
    ));
    assert_eq!(world.starts().len(), 1, "one prompt for all of them");

    // The answer was given: the user's next Connect asks again.
    assert!(matches!(
        launcher.ensure(HostMode::ElevatedSession).await,
        Err(LaunchError::ElevationDenied)
    ));
    assert_eq!(world.starts().len(), 2);
}

/// Only "no such pipe" lets a host start; anything unverifiable is
/// reported and nothing is started beside it.
#[tokio::test]
async fn an_unverifiable_session_pipe_fails_closed() {
    for answer in [Answer::Busy, Answer::Hangs] {
        let world = World::new(UiElevation::Limited, Start::Listens);
        world.answer(&session_pipe(), answer);
        let launcher = launcher(&world, false);
        let error = launcher
            .ensure(HostMode::ElevatedSession)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, LaunchError::Io(text) if text.contains("could not be verified")),
            "{answer:?}: {error:?}"
        );
        // Nothing chosen yet: probing logs it and finds nothing else.
        assert_eq!(launcher.probe().await.unwrap(), None);
        assert!(world.starts().is_empty(), "{answer:?}");
    }
}

/// opus nit 4: a same-user process holding the session pipe must not hide
/// the user's service or user host; it only blocks probing when the session
/// form is the saved choice.
#[tokio::test]
async fn an_unusable_session_pipe_blocks_probing_only_for_the_chosen_session_form() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host-choice");
    let choice = HostChoiceFile::new(&path);
    for answer in [Answer::Impostor, Answer::Busy, Answer::Hangs] {
        let world = World::new(UiElevation::Limited, Start::Listens);
        world.answer(&session_pipe(), answer);
        world.answer(&pipe("user"), Answer::Verified);
        let _ = std::fs::remove_file(&path);
        for saved in [None, Some(HostChoice::Service)] {
            if let Some(saved) = saved {
                choice.save(saved).unwrap();
            }
            let found = launcher_with(&world, false, true, Some(choice.clone()))
                .probe()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.mode, HostMode::User, "{answer:?} {saved:?}");
        }
        choice.save(HostChoice::ElevatedSession).unwrap();
        let result = launcher_with(&world, false, true, Some(choice.clone()))
            .probe()
            .await;
        assert!(
            matches!(
                result,
                Err(LaunchError::SessionRefused(_) | LaunchError::Io(_))
            ),
            "{answer:?}: {result:?}"
        );
        assert!(world.starts().is_empty());
    }
}
