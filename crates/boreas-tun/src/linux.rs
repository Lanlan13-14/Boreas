//! Linux packet-device adapter for an already-created and configured TUN queue.
//!
//! This module intentionally contains no ioctl or unsafe code. A separate privileged setup
//! component must create `/dev/net/tun`, configure `IFF_TUN|IFF_NO_PI` (and virtio header state),
//! set MTU/ownership, validate device/queue ownership, and pass the verified queue file here.
//! Adopting an arbitrary file descriptor does not itself prove that it is a TUN device.
use std::{fs::File, io::{self, Read, Write}, sync::Mutex};
use super::{inspect_packet, Error, PacketIo, MAX_IP_PACKET};

#[derive(Debug)]
pub enum LinuxTunError { InvalidConfiguration, Io(io::Error), Packet(Error), PartialWrite }
impl std::fmt::Display for LinuxTunError {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"{self:?}")}}
impl std::error::Error for LinuxTunError {}
impl From<io::Error> for LinuxTunError {fn from(e:io::Error)->Self{Self::Io(e)}}
impl From<Error> for LinuxTunError {fn from(e:Error)->Self{Self::Packet(e)}}

/// A single already-configured Linux TUN queue. Owns its fd and performs one read/write syscall
/// per L3 datagram; it does not create interfaces, configure offloads, or manage routes.
pub struct LinuxTun { file:Mutex<File>, mtu:usize }
impl LinuxTun {
 pub fn from_configured_file(file:File,mtu:usize)->Result<Self,LinuxTunError>{if !(68..=MAX_IP_PACKET).contains(&mtu){return Err(LinuxTunError::InvalidConfiguration)}Ok(Self{file:Mutex::new(file),mtu})}
 pub fn mtu(&self)->usize{self.mtu}
 pub fn into_file(self)->Result<File,LinuxTunError>{self.file.into_inner().map_err(|_|LinuxTunError::InvalidConfiguration)}
 pub fn read_validated(&self)->Result<Option<Vec<u8>>,LinuxTunError>{let mut buf=vec![0u8;self.mtu];let n=self.file.lock().map_err(|_|LinuxTunError::InvalidConfiguration)?.read(&mut buf)?;if n==0{return Ok(None)}buf.truncate(n);inspect_packet(&buf).map_err(LinuxTunError::Packet)?;Ok(Some(buf))}
 pub fn write_validated(&self,packet:&[u8])->Result<(),LinuxTunError>{if packet.len()>self.mtu{return Err(LinuxTunError::Packet(Error::PacketTooLarge{mtu:self.mtu}))}inspect_packet(packet).map_err(LinuxTunError::Packet)?;let n=self.file.lock().map_err(|_|LinuxTunError::InvalidConfiguration)?.write(packet)?;if n!=packet.len(){return Err(LinuxTunError::PartialWrite)}Ok(())}
}
impl PacketIo for LinuxTun {
 fn read_packet(&self)->Result<Option<Vec<u8>>,Error>{self.read_validated().map_err(|e|match e{LinuxTunError::Packet(p)=>p,_=>Error::QueueClosed})}
 fn write_packet(&self,packet:&[u8])->Result<(),Error>{self.write_validated(packet).map_err(|e|match e{LinuxTunError::Packet(p)=>p,_=>Error::QueueClosed})}
}

#[cfg(test)]mod tests{
 use super::*;
 #[test]fn mtu_is_bounded(){let f=File::open("/dev/null").unwrap();assert!(matches!(LinuxTun::from_configured_file(f,67),Err(LinuxTunError::InvalidConfiguration)));}
}
