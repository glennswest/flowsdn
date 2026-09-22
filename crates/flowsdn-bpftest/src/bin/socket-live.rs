//! Isolated real connect4/connect6 hook fixture. Only this process moves cgroups;
//! all sockets live in an anonymous network namespace with loopback only.
use aya::{
    EbpfLoader,
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
struct Cgroup {
    original: PathBuf,
    temporary: PathBuf,
    moved: bool,
}
impl Cgroup {
    fn create() -> Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let path = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or("unified cgroup v2 membership required")?;
        if !path.starts_with('/')
            || Path::new(path).components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err("unsafe cgroup membership path".into());
        }
        let original = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err("cgroup v2 mount required".into());
        }
        // Make a child of our own current cgroup, never relocate another task.
        let temporary = original.join(format!(
            "flowsdn-socket-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&temporary)?;
        let mut guard = Self {
            original,
            temporary,
            moved: false,
        };
        fs::write(
            guard.temporary.join("cgroup.procs"),
            std::process::id().to_string(),
        )?;
        guard.moved = true;
        Ok(guard)
    }
    fn restore(&mut self) -> Result<()> {
        if self.moved {
            fs::write(
                self.original.join("cgroup.procs"),
                std::process::id().to_string(),
            )?;
            self.moved = false;
        }
        fs::remove_dir(&self.temporary)?;
        Ok(())
    }
}
impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.moved {
            if let Err(error) = fs::write(
                self.original.join("cgroup.procs"),
                std::process::id().to_string(),
            ) {
                eprintln!("failed to restore own cgroup membership: {error}");
                return;
            }
            self.moved = false;
        }
        if let Err(error) = fs::remove_dir(&self.temporary)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("failed to remove owned temporary cgroup: {error}");
        }
    }
}
fn exchange(listener: &TcpListener, destination: SocketAddr, want: SocketAddr) -> Result<()> {
    let mut client = TcpStream::connect_timeout(&destination, Duration::from_secs(3))?;
    if client.peer_addr()? != want {
        return Err(format!(
            "connect rewrite mismatch: requested={destination}, observed={}, expected={want}",
            client.peer_addr()?
        )
        .into());
    }
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.set_write_timeout(Some(Duration::from_secs(3)))?;
    // connect completed before accept, so the local queue already has this peer.
    let (mut server, _) = listener.accept()?;
    server.set_read_timeout(Some(Duration::from_secs(3)))?;
    server.set_write_timeout(Some(Duration::from_secs(3)))?;
    client.write_all(b"flowsdn-socket-hook")?;
    let mut request = [0; 19];
    server.read_exact(&mut request)?;
    if &request != b"flowsdn-socket-hook" {
        return Err("server payload mismatch".into());
    }
    server.write_all(b"ok")?;
    let mut answer = [0; 2];
    client.read_exact(&mut answer)?;
    if &answer != b"ok" {
        return Err("client payload mismatch".into());
    }
    Ok(())
}
fn main() -> Result<()> {
    let object_path = std::env::args_os()
        .nth(1)
        .ok_or("usage: socket-live PATH_TO_SOCKET_CONTEXT_OBJECT")?;
    // No interfaces or routes from the original namespace remain accessible.
    unshare(CloneFlags::CLONE_NEWNET)?;
    let status = Command::new("ip")
        .args(["link", "set", "dev", "lo", "up"])
        .status()?;
    if !status.success() {
        return Err("failed to enable private loopback".into());
    }
    let mut cgroup = Cgroup::create()?;
    let cgroup_file = File::open(&cgroup.temporary)?;
    // Drop order keeps BPF links owned by object and detached before cgroup
    // restoration/removal, including all early-error paths.
    let mut object = EbpfLoader::new().load_file(object_path)?;
    for name in ["socket_connect4", "socket_connect6"] {
        let program: &mut CgroupSockAddr = object
            .program_mut(name)
            .ok_or("socket program missing")?
            .try_into()?;
        program.load()?;
        program.attach(&cgroup_file, CgroupAttachMode::Single)?;
    }
    for (loopback, service) in [
        (
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
        ),
        (
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("2001:db8::80".parse()?),
        ),
    ] {
        let expected = SocketAddr::new(loopback, 18080);
        let listener = TcpListener::bind(expected)?;
        exchange(&listener, SocketAddr::new(service, 80), expected)?;
        println!(
            "PASS real cgroup connect rewrite {service}:80 -> {expected}; peer address and TCP payload verified"
        );
        exchange(&listener, expected, expected)?;
        println!("PASS unmatched {expected} preserved with TCP payload verified");
    }
    drop(object);
    drop(cgroup_file);
    cgroup.restore()?;
    println!(
        "PASS own cgroup membership restored and temporary cgroup removed; anonymous network namespace exits with process"
    );
    Ok(())
}
