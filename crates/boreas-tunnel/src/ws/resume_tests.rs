use super::*;
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};

struct Paused {
    input:io::Cursor<Vec<u8>>,
    split:usize,
    resume:Arc<AtomicBool>,
    output:Vec<u8>,
}
impl Read for Paused {
    fn read(&mut self,out:&mut[u8])->io::Result<usize>{
        let pos=self.input.position() as usize;
        if !self.resume.load(Ordering::SeqCst) {
            if pos>=self.split {return Err(io::ErrorKind::WouldBlock.into());}
            let take=out.len().min(self.split-pos);
            self.input.read(&mut out[..take])
        } else {self.input.read(out)}
    }
}
impl Write for Paused {
    fn write(&mut self,bytes:&[u8])->io::Result<usize>{self.output.extend_from_slice(bytes);Ok(bytes.len())}
    fn flush(&mut self)->io::Result<()>{Ok(())}
}

#[test]
fn ws_partial_headers_masks_and_payloads_resume_once_without_poison() {
    for masked in [false,true] {
        for length in [1,125,126,8193] {
            let data=vec![0x73;length];
            let mut wire=vec![];
            encode_frame_into(masked,true,OpCode::Binary,&data,&mut wire).unwrap();
            for split in [1,2,3,5,7,wire.len()-1].into_iter().filter(|n|*n<wire.len()) {
                let resume=Arc::new(AtomicBool::new(false));
                let io=Paused{input:io::Cursor::new(wire.clone()),split,resume:resume.clone(),output:vec![]};
                let mut ws=WsStream::new(io,if masked {WsRole::Server}else{WsRole::Client},WsLimits::default());
                let mut out=vec![0;length];
                for _ in 0..3 {
                    assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
                    assert!(!ws.failed);
                }
                // A partial incoming frame cannot prevent an independent
                // outbound frame over a transport that can currently write.
                ws.write_all(b"reverse").unwrap();
                assert!(!ws.io.output.is_empty());
                resume.store(true,Ordering::SeqCst);
                ws.read_exact(&mut out).unwrap();
                assert_eq!(out,data);
                assert_eq!(ws.pending_pos,ws.pending.len());
                assert!(ws.receive_turn.is_none());
            }
        }
    }
}

#[test]
fn ws_receive_deadline_and_control_budget_survive_pending_calls() {
    let mut wire=vec![];
    encode_frame_into(true,true,OpCode::Binary,b"abc",&mut wire).unwrap();
    let resume=Arc::new(AtomicBool::new(false));
    let io=Paused{input:io::Cursor::new(wire),split:1,resume,output:vec![]};
    let mut ws=WsStream::new(io,WsRole::Server,WsLimits::default());
    let mut out=[0;4];
    assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
    ws.receive_turn.as_mut().unwrap().deadline=Instant::now();
    assert!(ws.read(&mut out).is_err());
    assert!(ws.failed);
    assert!(ws.receive_turn.is_none());

    let mut wire=vec![];
    encode_frame_into(true,true,OpCode::Pong,b"x",&mut wire).unwrap();
    let resume=Arc::new(AtomicBool::new(false));
    let io=Paused{input:io::Cursor::new(wire.clone()),split:wire.len(),resume:resume.clone(),output:vec![]};
    let mut ws=WsStream::new(io,WsRole::Server,WsLimits::default());
    assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
    assert_eq!(ws.receive_turn.as_ref().unwrap().controls,1);
    for _ in 0..3 {
        assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
        assert_eq!(ws.receive_turn.as_ref().unwrap().controls,1);
    }
}

struct OutputPaused {
    input:io::Cursor<Vec<u8>>, output:Vec<u8>, remaining:usize,
}
impl Read for OutputPaused {
    fn read(&mut self,out:&mut[u8])->io::Result<usize> {
        let n=self.input.read(out)?;
        if n==0 {Err(io::ErrorKind::WouldBlock.into())}else{Ok(n)}
    }
}
impl Write for OutputPaused {
    fn write(&mut self,bytes:&[u8])->io::Result<usize> {
        if self.remaining==0 {return Err(io::ErrorKind::WouldBlock.into());}
        let n=bytes.len().min(self.remaining);self.remaining-=n;
        self.output.extend_from_slice(&bytes[..n]);Ok(n)
    }
    fn flush(&mut self)->io::Result<()>{Ok(())}
}
impl crate::stream::Duplex for OutputPaused {
    fn has_buffered_input(&self)->bool {false}
    fn enable_progress(&mut self)->io::Result<bool>{Ok(true)}
}
#[test]
fn pending_binary_keeps_mask_and_prefix_when_ping_needs_output() {
    let mut ping=vec![];
    let ping_len=encode_frame_into(false,true,OpCode::Ping,b"probe",&mut ping).unwrap().len();
    ping.truncate(ping_len);
    let transport=OutputPaused{input:io::Cursor::new(ping),output:vec![],remaining:3};
    let mut ws=WsStream::new(transport,WsRole::Client,WsLimits::default());
    ws.enable_transport_progress().unwrap();
    assert_eq!(ws.write(b"payload").unwrap_err().kind(),io::ErrorKind::WouldBlock);
    let encoded=ws.write_buf.clone();
    let deadline=ws.write_deadline;
    let mut out=[0;16];
    for _ in 0..3 {
        assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
        assert_eq!(ws.write_buf,encoded);
        assert_eq!(ws.write_deadline,deadline);
        assert!(!ws.failed);
    }
    ws.io.remaining=usize::MAX;
    ws.progress_transport_io().unwrap();
    assert_eq!(ws.io.output,encoded);
    assert_eq!(ws.write(b"payload").unwrap(),7);
    ws.progress_transport_io().unwrap();
    let mut cursor=io::Cursor::new(ws.io.output.clone());
    let first=read_frame(&mut cursor,WsRole::Server,&WsLimits::default(),Instant::now()+Duration::from_secs(1)).unwrap();
    let second=read_frame(&mut cursor,WsRole::Server,&WsLimits::default(),Instant::now()+Duration::from_secs(1)).unwrap();
    assert_eq!(first.opcode,OpCode::Binary);assert_eq!(first.payload,b"payload");
    assert_eq!(second.opcode,OpCode::Pong);assert_eq!(second.payload,b"probe");
    assert_eq!(cursor.position() as usize,cursor.get_ref().len());
}
#[test]
fn empty_nonblocking_reads_do_not_start_a_peer_frame_deadline() {
    let io=OutputPaused{input:io::Cursor::new(vec![]),output:vec![],remaining:usize::MAX};
    let mut ws=WsStream::new(io,WsRole::Server,WsLimits::default());
    let mut out=[0;8];
    for _ in 0..8 {
        assert_eq!(ws.read(&mut out).unwrap_err().kind(),io::ErrorKind::WouldBlock);
        assert!(ws.receive_turn.is_none());assert!(!ws.failed);
    }
}
#[test]
fn pending_ws_write_keeps_original_absolute_deadline() {
    let io=OutputPaused{input:io::Cursor::new(vec![]),output:vec![],remaining:1};
    let mut ws=WsStream::new(io,WsRole::Client,WsLimits::default());
    assert_eq!(ws.write(b"pending").unwrap_err().kind(),io::ErrorKind::WouldBlock);
    ws.write_deadline=Some(Instant::now());
    assert!(ws.write(b"pending").is_err());assert!(ws.failed);
}
