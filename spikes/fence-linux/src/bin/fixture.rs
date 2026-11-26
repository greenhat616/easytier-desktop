use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process,
    time::Duration,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    let command = args[1].as_str();
    if command == "listen" {
        let listener = TcpListener::bind(&args[2])?;
        fs::write(&args[3], format!("{}", process::id()))?;
        println!(
            "LISTEN pid={} endpoint={}",
            process::id(),
            listener.local_addr()?
        );
        for stream in listener.incoming() {
            let mut stream = stream?;
            let _ = stream.write_all(args[4].as_bytes());
        }
    } else if command == "probe" {
        let endpoint: SocketAddr = args[2].parse()?;
        let token = args[3].as_bytes();
        let want = &args[4];
        let result = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3));
        let status = match result {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                let mut bytes = vec![0; token.len()];
                stream.read_exact(&mut bytes)?;
                if bytes != token {
                    return Err("wrong listener token".into());
                }
                "allowed"
            }
            Err(e) => {
                println!("CONNECT_ERROR {endpoint}: {e:?}");
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::PermissionDenied => "denied",
                    _ => return Err(e.into()),
                }
            }
        };
        println!("PROBE {endpoint} expected={want} actual={status}");
        if status != want {
            return Err("unexpected connect decision".into());
        }
    } else if command == "hold" {
        fs::write(&args[2], process::id().to_string())?;
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    } else {
        return Err("unknown command".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL: {e}");
        process::exit(1);
    }
}
