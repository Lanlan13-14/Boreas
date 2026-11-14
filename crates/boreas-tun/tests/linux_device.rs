#![cfg(target_os = "linux")]

use boreas_tun::linux::{LinuxTunDevice, TunConfig};
use std::{fs, net::Ipv4Addr, process::Command, time::{Duration, Instant}};

fn root() -> bool { unsafe { libc::geteuid() == 0 } }
fn rerun_in_netns(test_name:&str){
    assert!(root(),"linux-system test requires root");
    let exe=std::env::current_exe().expect("test executable path");
    let status=Command::new("unshare").args(["--net","--mount","--fork"]).arg(exe).args(["--exact",test_name,"--nocapture"]).env("BOREAS_IN_NETNS","1").status().expect("unshare");
    assert!(status.success(),"isolated Linux network namespace test failed");
}
fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().expect("iproute2 installed by linux-system workflow");
    assert!(out.status.success(), "ip {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}
struct DeviceCleanup(String);
impl Drop for DeviceCleanup { fn drop(&mut self){ let _=Command::new("ip").args(["link","del","dev",&self.0]).status(); } }
fn unique_name() -> String {
    // Linux IFNAMSIZ is 16 including NUL. Process id plus atomic gives tests isolated names.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    format!("bt{:x}{:x}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}
fn ipv4_checksum(b: &[u8]) -> u16 {
    let mut sum=0u32;
    for x in b.chunks(2) { sum += if x.len()==2 {u16::from_be_bytes([x[0],x[1]]) as u32} else {(x[0] as u32)<<8}; }
    while sum>>16!=0 { sum=(sum&0xffff)+(sum>>16); }
    !(sum as u16)
}
fn echo_packet(src:Ipv4Addr,dst:Ipv4Addr)->Vec<u8> {
    let mut p=vec![0u8;28];p[0]=0x45;p[2..4].copy_from_slice(&28u16.to_be_bytes());p[8]=64;p[9]=1;
    p[12..16].copy_from_slice(&src.octets());p[16..20].copy_from_slice(&dst.octets());
    p[20]=8;p[24..26].copy_from_slice(&1u16.to_be_bytes());p[26..28].copy_from_slice(&1u16.to_be_bytes());
    let ic=ipv4_checksum(&p[20..]);p[22..24].copy_from_slice(&ic.to_be_bytes());
    let ih=ipv4_checksum(&p[..20]);p[10..12].copy_from_slice(&ih.to_be_bytes());p
}

#[test]
fn create_verify_mtu_multiqueue_and_auto_cleanup() {
    if std::env::var_os("BOREAS_IN_NETNS").is_none() { rerun_in_netns("create_verify_mtu_multiqueue_and_auto_cleanup"); return; }
    if !root() { panic!("linux-system test must execute as root to configure a real TUN device"); }
    let name=unique_name();
    let (device,queue)=LinuxTunDevice::create(TunConfig{name:Some(name.clone()),mtu:1400,multi_queue:true,vnet_header:false}).expect("create Linux TUN with TUNSETIFF");
    let _cleanup=DeviceCleanup(name.clone());
    assert_eq!(device.name(),name);assert_eq!(queue.device_name(),name);queue.verify().expect("TUNGETIFF verifies device/flags");
    let sysfs=format!("/sys/class/net/{name}/mtu");assert_eq!(fs::read_to_string(&sysfs).unwrap().trim(),"1400");
    let second=device.attach_queue().expect("attach second MULTI_QUEUE fd");second.verify().expect("verify attached queue");
    drop(second);drop(queue);drop(device);
    assert!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists(),"non-persistent TUN should disappear with all owning fds");
}

#[test]
fn real_l3_write_and_kernel_routed_reply() {
    if std::env::var_os("BOREAS_IN_NETNS").is_none() { rerun_in_netns("real_l3_write_and_kernel_routed_reply"); return; }
    if !root() { panic!("linux-system test must execute as root to configure a real TUN device"); }
    let name=unique_name();
    let (device,queue)=LinuxTunDevice::create(TunConfig{name:Some(name.clone()),mtu:1400,multi_queue:false,vnet_header:false}).expect("create TUN");
    let _cleanup=DeviceCleanup(name.clone());
    ip(&["link","set","dev",&name,"up"]);
    ip(&["addr","add","198.18.0.1/30","dev",&name]);
    // Packet injection into the host stack should produce an ICMP echo reply routed back through
    // this TUN interface; this tests actual queue read/write, IP stack, route and configured MTU.
    let req=echo_packet(Ipv4Addr::new(198,18,0,2),Ipv4Addr::new(198,18,0,1));
    queue.write_packet(&req).expect("write valid packet into kernel through TUN");
    let until=Instant::now()+Duration::from_secs(3);let mut reply=None;
    while Instant::now()<until {
        match queue.read_packet_timeout(Duration::from_millis(100)) {
            Ok(Some(p))=>{reply=Some(p);break},
            Ok(None)=>{},
            Err(other)=>panic!("TUN read returned unexpected result: {other:?}"),
        }
    }
    let p=reply.expect("kernel should route the echo reply out through the TUN");
    assert_eq!(p[0]>>4,4);assert_eq!(p[9],1);assert_eq!(p[20],0,"ICMP echo reply");
    drop(queue);drop(device);
}
