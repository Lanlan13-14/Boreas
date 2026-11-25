//! Incremental receive owner for one WS frame. Header, mask and body offsets
//! survive WouldBlock; no peer length allocates bytes before header checks.
use super::*;

pub(super) struct Incoming {
    head: [u8;14],
    have: usize,
    need: usize,
    parsed: Option<(bool,OpCode,usize,Option<[u8;4]>)>,
    payload: Vec<u8>,
    body_have: usize,
}
impl Incoming {
    pub(super) fn new(payload: Vec<u8>) -> Self {
        Self { head:[0;14],have:0,need:2,parsed:None,payload,body_have:0 }
    }
    fn header(&mut self, role: WsRole, limits: &WsLimits) -> Result<bool,WsError> {
        if self.have<2 { return Ok(false); }
        let fin=self.head[0]&0x80!=0;
        if self.head[0]&0x70!=0 { return Err(WsError::ReservedBits); }
        let opcode=OpCode::from_bits(self.head[0]&15)?;
        let masked=self.head[1]&0x80!=0;
        match role {
            WsRole::Server if !masked => return Err(WsError::UnmaskedClientFrame),
            WsRole::Client if masked => return Err(WsError::MaskedServerFrame),
            _=>{}
        }
        let code=self.head[1]&127;
        let extended=match code {126=>2,127=>8,_=>0};
        self.need=2+extended;
        if self.have<self.need { return Ok(false); }
        let length=match code {
            126=> {let n=usize::from(u16::from_be_bytes([self.head[2],self.head[3]]));
                if n<126 {return Err(WsError::NonCanonicalLength);} n},
            127=> {let n=u64::from_be_bytes(self.head[2..10].try_into().expect("header length checked"));
                if n<65536 {return Err(WsError::NonCanonicalLength);}
                usize::try_from(n).map_err(|_|WsError::MessageTooLarge)?},
            n=>usize::from(n),
        };
        if opcode.is_control() {
            if !fin {return Err(WsError::ControlFragmented);}
            if length>125 {return Err(WsError::ControlTooLarge);}
        }
        if length>limits.max_frame_payload {return Err(WsError::MessageTooLarge);}
        self.need=2+extended+if masked {4}else{0};
        if self.have<self.need {return Ok(false);}
        let mask=masked.then(||self.head[self.need-4..self.need].try_into().expect("mask length checked"));
        self.parsed=Some((fin,opcode,length,mask));
        self.payload.clear();
        Ok(true)
    }
    pub(super) fn receive<R:Read>(&mut self, io:&mut R, role:WsRole, limits:&WsLimits, deadline:Instant)
        -> Result<RawFrame,WsError>
    {
        loop {
            if Instant::now()>=deadline {return Err(WsError::Timeout);}
            if let Some((fin,opcode,length,mask)) = self.parsed {
                if self.body_have==length {
                    if let Some(mask)=mask {unmask_payload(&mut self.payload,mask);}
                    if Instant::now()>=deadline {return Err(WsError::Timeout);}
                    return Ok(RawFrame{fin,opcode,payload:std::mem::take(&mut self.payload)});
                }
                // Growth is driven by bytes about to be read, not peer's full
                // declaration; retained storage remains bounded by frame cap.
                let end=length.min(self.body_have+8192);
                self.payload.resize(end,0);
                let n=match io.read(&mut self.payload[self.body_have..end]) {
                    Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{
                        self.payload.truncate(self.body_have);
                        return Err(WsError::Io(io::ErrorKind::WouldBlock));
                    }
                    result=>result.map_err(map_io)?,
                };
                if n==0 {return Err(WsError::Closed);}
                self.body_have+=n;
                self.payload.truncate(self.body_have);
            } else {
                if self.header(role,limits)? {continue;}
                let n=match io.read(&mut self.head[self.have..self.need]) {
                    Err(e) if e.kind()==io::ErrorKind::WouldBlock=>return Err(WsError::Io(io::ErrorKind::WouldBlock)),
                    result=>result.map_err(map_io)?,
                };
                if n==0 {return Err(WsError::Closed);}
                self.have+=n;
            }
            if Instant::now()>=deadline {return Err(WsError::Timeout);}
        }
    }
}

pub(super) struct ReceiveTurn {
    pub(super) deadline:Instant,
    pub(super) frames:usize,
    pub(super) controls:usize,
    pub(super) control_bytes:usize,
    pub(super) incoming:Option<Incoming>,
}
impl ReceiveTurn {
    pub(super) fn new(duration:Duration)->Self {
        Self{deadline:Instant::now()+duration,frames:0,controls:0,control_bytes:0,incoming:None}
    }
}
