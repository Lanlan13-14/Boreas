//! Bounded metadata parser. Kept separate from the supervisor's signed schema.

use std::collections::BTreeMap;

use super::Issue;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    One,
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Value {
    pub(crate) fn get(&self, key: &str) -> Result<&Self, Issue> {
        match self {
            Self::Object(fields) => fields.get(key).ok_or(Issue::Invalid),
            _ => Err(Issue::Invalid),
        }
    }

    pub(crate) fn boolean(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[cfg(unix)]
    pub(crate) fn unsigned(&self) -> Option<u64> {
        match self {
            Self::One => Some(1),
            Self::Number(raw) if raw.bytes().all(|b| b.is_ascii_digit()) => raw.parse().ok(),
            _ => None,
        }
    }
}

pub(super) const MAX_BYTES: usize = 1024 * 1024;
const MAX_NODES: usize = 32_768;
const MAX_DEPTH: usize = 32;

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Issue> {
    if bytes.len() > MAX_BYTES {
        return Err(Issue::TooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| Issue::Invalid)?;
    let mut parser = Parser { rest: bytes, remaining: MAX_NODES };
    let value = parser.value(0)?;
    parser.whitespace();
    if !parser.rest.is_empty() {
        return Err(Issue::Invalid);
    }
    Ok(value)
}

struct Parser<'a> {
    rest: &'a [u8],
    remaining: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.rest = &self.rest[1..];
            true
        } else {
            false
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.rest = &self.rest[1..];
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Issue> {
        if depth > MAX_DEPTH || self.remaining == 0 {
            return Err(Issue::Invalid);
        }
        self.remaining -= 1;
        self.whitespace();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[') => {
                let mut values = Vec::new();
                self.sequence(b']', |parser| {
                    values.push(parser.value(depth + 1)?);
                    Ok(())
                })?;
                Ok(Value::Array(values))
            }
            Some(b'{') => {
                let mut fields = BTreeMap::new();
                self.sequence(b'}', |parser| {
                    let key = parser.string()?;
                    parser.whitespace();
                    if !parser.take(b':') {
                        return Err(Issue::Invalid);
                    }
                    let value = parser.value(depth + 1)?;
                    if fields.insert(key, value).is_some() {
                        return Err(Issue::Invalid);
                    }
                    Ok(())
                })?;
                Ok(Value::Object(fields))
            }
            _ => Err(Issue::Invalid),
        }
    }

    fn sequence(
        &mut self,
        end: u8,
        mut entry: impl FnMut(&mut Self) -> Result<(), Issue>,
    ) -> Result<(), Issue> {
        self.rest = &self.rest[1..];
        self.whitespace();
        if self.take(end) {
            return Ok(());
        }
        loop {
            entry(self)?;
            self.whitespace();
            if self.take(end) {
                return Ok(());
            }
            if !self.take(b',') {
                return Err(Issue::Invalid);
            }
            self.whitespace();
        }
    }

    fn literal(&mut self, raw: &[u8], value: Value) -> Result<Value, Issue> {
        self.rest = self.rest.strip_prefix(raw).ok_or(Issue::Invalid)?;
        Ok(value)
    }

    fn consume_digits(&mut self) -> Result<(), Issue> {
        let count = self.rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if count == 0 {
            return Err(Issue::Invalid);
        }
        self.rest = &self.rest[count..];
        Ok(())
    }

    fn number(&mut self) -> Result<Value, Issue> {
        let start = self.rest;
        self.take(b'-');
        if !self.take(b'0') {
            self.consume_digits()?;
        }
        if self.take(b'.') {
            self.consume_digits()?;
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            self.consume_digits()?;
        }
        Ok(if &start[..start.len() - self.rest.len()] == b"1" {
            Value::One
        } else {
            Value::Number(std::str::from_utf8(&start[..start.len() - self.rest.len()])
                .map_err(|_| Issue::Invalid)?.to_string())
        })
    }

    fn hex4(&mut self) -> Result<u16, Issue> {
        let bytes = self.rest.get(..4).ok_or(Issue::Invalid)?;
        let hex = std::str::from_utf8(bytes).map_err(|_| Issue::Invalid)?;
        if !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(Issue::Invalid);
        }
        let code = u16::from_str_radix(hex, 16).map_err(|_| Issue::Invalid)?;
        self.rest = &self.rest[4..];
        Ok(code)
    }

    fn escaped(&mut self) -> Result<char, Issue> {
        let (&byte, tail) = self.rest.split_first().ok_or(Issue::Invalid)?;
        self.rest = tail;
        Ok(match byte {
            b'"' | b'\\' | b'/' => char::from(byte),
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = self.hex4()?;
                let code = if (0xd800..=0xdbff).contains(&high) {
                    self.rest = self.rest.strip_prefix(b"\\u").ok_or(Issue::Invalid)?;
                    let low = self.hex4()?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(Issue::Invalid);
                    }
                    0x10000 + (u32::from(high - 0xd800) << 10) + u32::from(low - 0xdc00)
                } else {
                    u32::from(high)
                };
                char::from_u32(code).ok_or(Issue::Invalid)?
            }
            _ => return Err(Issue::Invalid),
        })
    }

    fn string(&mut self) -> Result<String, Issue> {
        if !self.take(b'"') {
            return Err(Issue::Invalid);
        }
        let mut value = String::new();
        loop {
            let stop = self
                .rest
                .iter()
                .position(|&b| matches!(b, b'"' | b'\\' | 0..=31));
            let (stop, byte) = stop.map(|pos| (pos, self.rest[pos])).ok_or(Issue::Invalid)?;
            let segment = std::str::from_utf8(&self.rest[..stop]).map_err(|_| Issue::Invalid)?;
            value.push_str(segment);
            self.rest = &self.rest[stop + 1..];
            match byte {
                b'"' => return Ok(value),
                b'\\' => value.push(self.escaped()?),
                _ => return Err(Issue::Invalid),
            }
        }
    }
}
