use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

const BUF_SIZE: usize = 8 * 1024;

enum State {
    Read,
    Write(usize, usize),
}

pub struct Worker<'a> {
    buf: Vec<u8>,
    state: State,
    from: &'a TcpStream,
    to: &'a TcpStream,
}

impl<'a> Worker<'a> {
    pub fn new(from: &'a TcpStream, to: &'a TcpStream) -> Self {
        Self {
            buf: vec![0; BUF_SIZE],
            state: State::Read,
            from,
            to,
        }
    }

    pub fn run(&mut self) -> bool {
        match self.state {
            State::Read => match self.from.read(&mut self.buf) {
                Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock => (),

                Err(..) | Ok(0) => return false,

                Ok(len) => self.state = State::Write(0, len),
            },

            State::Write(start, end) => match self.to.write(&self.buf[start..end]) {
                Err(ref e) if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::WouldBlock => (),

                Err(..) | Ok(0) => return false,

                Ok(len) if start + len < end => self.state = State::Write(start + len, end),

                Ok(..) => self.state = State::Read,
            },
        }

        true
    }
}
