//! The elevated session form's decisions (doc#13 #choose #sequence), with
//! scripted connectors, a scripted token and a scripted starter: which host
//! is used, when exactly one start happens, how cancelled prompts and early
//! exits are reported, and that nothing starts without `ensure`.
use async_trait::async_trait;
use etd_app::launcher_session::{
    ElevatedSessionConfig, ElevationStarter, HostChoice, HostChoiceFile, RECLAIM_ALL_USERS_ARGS,
    RECLAIM_ARGS, SESSION_HOST_ARGS, SessionParts, StartError, StartedProcess, UiElevation,
    reclaim_session_leftovers, refusal_of,
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
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Answer {
    Verified,
    Absent,
    Impostor,
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
}

impl World {
    fn new(elevation: UiElevation, start: Start) -> Self {
        Self {
            answers: Arc::default(),
            elevation: Arc::new(Mutex::new(elevation)),
            start: Arc::new(Mutex::new(start)),
            starts: Arc::default(),
            user_spawns: Arc::default(),
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
            Answer::Absent => Err(io::ErrorKind::NotFound.into()),
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
    LocalHostLauncher::with_parts(
        Some(service_config(service_installed)),
        None,
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
    assert!(matches!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)),
        Err(LaunchError::ElevationDenied)
    ));
    let world = World::new(UiElevation::Elevated, Start::Exits(5));
    assert!(matches!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_secs(1)),
        Err(LaunchError::SessionRefused(
            SessionRefusal::OtherUsersLeftovers
        ))
    ));
    let world = World::new(UiElevation::Elevated, Start::StaysSilent);
    assert!(matches!(
        reclaim_session_leftovers(&world, &program(), false, Duration::from_millis(50)),
        Err(LaunchError::Timeout)
    ));
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
