//! Finding and starting hosts, with scripted connectors and processes.
use async_trait::async_trait;
use etd_app::launcher_user::{
    ConnectorFactory, HostSpawner, LauncherTimings, LocalHostLauncher, ServiceHostConfig,
    SpawnedHost, TokioSpawner, USER_HOST_ARGS, UserHostConfig,
};
use etd_app::{HostLauncher, LaunchError};
use etd_contract::HostMode;
use etd_ipc::{
    BoxConn, Connector, Endpoint, OsUserId, PeerIdentity, ServerExpectation, ServerIdentity,
    ServerRequirement,
};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Answer {
    Verified,
    Absent,
    Impostor,
}

/// What each endpoint answers.
#[derive(Clone, Default)]
struct World {
    answers: Arc<Mutex<HashMap<Endpoint, Answer>>>,
    spawns: Arc<Mutex<u32>>,
    /// What a spawned host does: when it starts answering, whether it dies.
    start: Arc<Mutex<Start>>,
}

#[derive(Debug, Clone, Copy, Default)]
enum Start {
    #[default]
    Listens,
    StaysSilent,
    Exits,
    ExitsBecauseAnotherHostAnswers,
    CannotSpawn,
}

impl World {
    fn answer(&self, endpoint: &Endpoint, answer: Answer) {
        self.answers
            .lock()
            .unwrap()
            .insert(endpoint.clone(), answer);
    }
    fn spawns(&self) -> u32 {
        *self.spawns.lock().unwrap()
    }
    fn on_start(&self, start: Start) {
        *self.start.lock().unwrap() = start;
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
                "unexpected server image",
            )),
            Answer::Verified => {
                let (client, _server) = tokio::io::duplex(8);
                let identity = ServerIdentity {
                    peer: PeerIdentity {
                        user: OsUserId::UnixUid(1000),
                        groups: Vec::new(),
                        pid: 1,
                        session: None,
                        elevated: false,
                    },
                    exe: PathBuf::from("etd-host"),
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

struct Process(Option<String>);

impl SpawnedHost for Process {
    fn try_exit(&mut self) -> io::Result<Option<String>> {
        Ok(self.0.clone())
    }
}

impl HostSpawner for World {
    fn spawn(&self, config: &UserHostConfig) -> io::Result<Box<dyn SpawnedHost>> {
        *self.spawns.lock().unwrap() += 1;
        let start = *self.start.lock().unwrap();
        match start {
            Start::CannotSpawn => Err(io::ErrorKind::NotFound.into()),
            Start::Listens => {
                self.answer(&config.endpoint, Answer::Verified);
                Ok(Box::new(Process(None)))
            }
            Start::StaysSilent => Ok(Box::new(Process(None))),
            Start::Exits => Ok(Box::new(Process(Some("exit code: 2".into())))),
            Start::ExitsBecauseAnotherHostAnswers => {
                self.answer(&config.endpoint, Answer::Verified);
                Ok(Box::new(Process(Some("exit code: 0".into()))))
            }
        }
    }
}

fn pipe(name: &str) -> Endpoint {
    Endpoint::NamedPipe(name.into())
}

fn user_config() -> UserHostConfig {
    UserHostConfig {
        program: "etd-host".into(),
        args: USER_HOST_ARGS.iter().map(Into::into).collect(),
        endpoint: pipe("user"),
        expectation: ServerExpectation {
            exe_dir: "dir".into(),
            requirement: ServerRequirement::CurrentUser,
        },
    }
}

/// `installed` decides whether the program file exists.
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

fn launcher(world: &World, installed: bool) -> LocalHostLauncher {
    LocalHostLauncher::with_parts(
        Some(service_config(installed)),
        Some(user_config()),
        Arc::new(world.clone()),
        Arc::new(world.clone()),
        LauncherTimings {
            startup: Duration::from_millis(80),
            poll: Duration::from_millis(5),
            connect: Duration::from_millis(50),
        },
    )
}

#[tokio::test]
async fn probe_prefers_the_service_and_starts_nothing() {
    let world = World::default();
    assert_eq!(launcher(&world, false).probe().await.unwrap(), None);

    // Installed but not answering is still the host to connect to.
    let found = launcher(&world, true).probe().await.unwrap().unwrap();
    assert_eq!(found.mode, HostMode::Service);

    world.answer(&pipe("user"), Answer::Verified);
    let found = launcher(&world, false).probe().await.unwrap().unwrap();
    assert_eq!(found.mode, HostMode::User);

    world.answer(&pipe("service"), Answer::Verified);
    let found = launcher(&world, false).probe().await.unwrap().unwrap();
    assert_eq!(found.mode, HostMode::Service);
    assert_eq!(found.expectation.requirement, ServerRequirement::Service);
    assert_eq!(world.spawns(), 0);
}

#[tokio::test]
async fn ensure_user_starts_one_host_and_reuses_it() {
    let world = World::default();
    let launcher = Arc::new(launcher(&world, false));
    let (first, second) = tokio::join!(
        launcher.ensure(HostMode::User),
        launcher.ensure(HostMode::User)
    );
    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(world.spawns(), 1);

    // It vanished: the next call starts it again.
    world.answer(&pipe("user"), Answer::Absent);
    world.on_start(Start::Exits);
    let result = launcher.ensure(HostMode::User).await;
    // The first process still reports running, so it is waited for.
    assert!(matches!(result, Err(LaunchError::Timeout)), "{result:?}");
    assert_eq!(world.spawns(), 1);
}

#[tokio::test]
async fn a_slow_host_is_not_started_twice() {
    let world = World::default();
    world.on_start(Start::StaysSilent);
    let launcher = launcher(&world, false);
    for _ in 0..2 {
        assert!(matches!(
            launcher.ensure(HostMode::User).await,
            Err(LaunchError::Timeout)
        ));
    }
    assert_eq!(world.spawns(), 1);
    world.answer(&pipe("user"), Answer::Verified);
    assert!(launcher.ensure(HostMode::User).await.is_ok());
    assert_eq!(world.spawns(), 1);
}

#[tokio::test]
async fn start_up_failures_are_typed() {
    let world = World::default();
    world.on_start(Start::Exits);
    let launcher = launcher(&world, false);
    for expected_spawns in 1..=2 {
        match launcher.ensure(HostMode::User).await {
            Err(LaunchError::Spawn(reason)) => assert!(reason.contains("exit code: 2")),
            other => panic!("{other:?}"),
        }
        assert_eq!(world.spawns(), expected_spawns);
    }
    world.on_start(Start::CannotSpawn);
    assert!(matches!(
        launcher.ensure(HostMode::User).await,
        Err(LaunchError::Spawn(_))
    ));
    world.on_start(Start::ExitsBecauseAnotherHostAnswers);
    assert!(launcher.ensure(HostMode::User).await.is_ok());
}

#[tokio::test]
async fn nothing_is_started_over_an_impostor() {
    let world = World::default();
    world.answer(&pipe("user"), Answer::Impostor);
    let launcher = launcher(&world, false);
    for result in [
        launcher.ensure(HostMode::User).await.map(Some),
        launcher.probe().await,
    ] {
        match result {
            Err(LaunchError::Io(reason)) => assert!(reason.contains("verification")),
            other => panic!("{other:?}"),
        }
    }
    world.answer(&pipe("service"), Answer::Impostor);
    assert!(matches!(
        launcher.ensure(HostMode::Service).await,
        Err(LaunchError::Io(_))
    ));
    assert_eq!(world.spawns(), 0);
}

/// The Unix connector reports a missing socket as refused. That must still
/// start the host.
#[tokio::test]
async fn a_missing_socket_is_absent_not_an_impostor() {
    let world = World::default();
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::UnixSocket(dir.path().join("private/host.sock"));
    world.answer(&endpoint, Answer::Impostor);
    world.on_start(Start::StaysSilent);
    let mut config = user_config();
    config.endpoint = endpoint;
    let launcher = LocalHostLauncher::with_parts(
        None,
        Some(config),
        Arc::new(world.clone()),
        Arc::new(world.clone()),
        LauncherTimings {
            startup: Duration::from_millis(30),
            poll: Duration::from_millis(5),
            connect: Duration::from_millis(50),
        },
    );
    assert_eq!(launcher.probe().await.unwrap(), None);
    assert!(matches!(
        launcher.ensure(HostMode::User).await,
        Err(LaunchError::Timeout)
    ));
    assert_eq!(world.spawns(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("private"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[tokio::test]
async fn service_and_elevated_forms() {
    let world = World::default();
    assert!(matches!(
        launcher(&world, false).ensure(HostMode::Service).await,
        Err(LaunchError::NotInstalled)
    ));
    assert!(matches!(
        launcher(&world, true).ensure(HostMode::Service).await,
        Err(LaunchError::Timeout)
    ));
    world.answer(&pipe("service"), Answer::Verified);
    assert!(
        launcher(&world, false)
            .ensure(HostMode::Service)
            .await
            .is_ok()
    );
    for form in [HostMode::ElevatedSession, HostMode::Unspecified] {
        assert!(matches!(
            launcher(&world, true).ensure(form).await,
            Err(LaunchError::Unsupported(f)) if f == form
        ));
    }
    assert_eq!(world.spawns(), 0);
}

#[test]
fn the_standard_user_host_matches_the_host_command_line() {
    let program = std::env::current_exe().unwrap();
    let config = UserHostConfig::standard(program.clone()).unwrap();
    assert_eq!(config.args, ["run", "--mode", "user"]);
    assert_eq!(
        config.expectation.requirement,
        ServerRequirement::CurrentUser
    );
    assert_eq!(config.expectation.exe_dir, program.parent().unwrap());
    match (&config.endpoint, etd_ipc::platform::current_user().unwrap()) {
        (Endpoint::NamedPipe(name), OsUserId::WindowsSid(sid)) => {
            assert_eq!(*name, format!(r"\\.\pipe\easytier-desk-user-{sid}"));
        }
        (Endpoint::UnixSocket(path), OsUserId::UnixUid(_)) => {
            assert!(path.ends_with("host.sock"), "{path:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn the_real_spawner_reports_an_exit() {
    let mut config = user_config();
    // The test binary itself, asked to run no test: exits at once.
    config.program = std::env::current_exe().unwrap();
    config.args = vec!["--exact".into(), "no-such-test".into()];
    let mut process = TokioSpawner.spawn(&config).unwrap();
    for _ in 0..500 {
        if process.try_exit().unwrap().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the child never exited");
}
