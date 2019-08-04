mod worker;

use simple_error::{SimpleError, SimpleResult as Result};
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use tls_parser::tls_extensions::SNIType;
use tls_parser::{TlsClientHelloContents, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext};
use worker::Worker;

const MAX_TSL_LENGTH: usize = 16384;

fn main() {
    let listener = TcpListener::bind(("0.0.0.0", 443)).unwrap();

    for stream in listener.incoming() {
        stream
            .map_err(SimpleError::from)
            .and_then(|stream| handle_client(stream))
            .unwrap_or_else(|e| eprintln!("Error: {}", e));
    }
}

fn handle_client(mut client: TcpStream) -> Result<()> {
    let mut buffer = Vec::new();

    let record = read_tls_record(&mut client, &mut buffer)?;

    let server_name = extract_server_name(&record.msg[0])?;

    let mut server = TcpStream::connect((&server_name[..], 443)).map_err(SimpleError::from)?;

    server.write_all(&buffer).map_err(SimpleError::from)?;

    spawn_copy_thread(server_name, client, server);

    Ok(())
}

fn read_tls_record<'a>(stream: &'a mut TcpStream, buffer: &'a mut Vec<u8>) -> Result<TlsPlaintext<'a>> {
    buffer.resize(5, 0);

    stream.read_exact(buffer).map_err(SimpleError::from)?;

    let length = (buffer[3] as usize) << 8 + buffer[4];

    if length > MAX_TSL_LENGTH {
        return Err(SimpleError::new(format!(
            "Failed to parse TLS record: length is too big ({})",
            length
        )));
    }

    buffer.resize(5 + length, 0);

    stream.read_exact(&mut buffer[5..]).map_err(SimpleError::from)?;

    tls_parser::parse_tls_plaintext(buffer)
        .map_err(|e| SimpleError::new(format!("Failed to parse TLS record: {:?}", e)))
        .map(|(_, parsed)| parsed)
}

fn extract_server_name(message: &TlsMessage) -> Result<String> {
    match message {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(TlsClientHelloContents { ext: Some(ext), .. })) => {
            let (_, extensions) = tls_parser::parse_tls_extensions(ext)
                .map_err(|e| SimpleError::new(format!("Failed to parse TLS extensions: {:?}", e)))?;

            for ext in extensions {
                if let TlsExtension::SNI(sni) = ext {
                    for (name_type, name) in sni {
                        if name_type == SNIType::HostName {
                            return String::from_utf8(name.to_vec()).map_err(SimpleError::from);
                        }
                    }
                }
            }

            Err("Failed to find SNI extension".into())
        }

        _ => Err("Expected a client hello message with extensions".into()),
    }
}

fn spawn_copy_thread(id: String, client: TcpStream, server: TcpStream) {
    thread::spawn(move || {
        eprintln!("{} thread started", id);

        client.set_nonblocking(true).unwrap();

        server.set_nonblocking(true).unwrap();

        let mut cs = Worker::new(&client, &server);

        let mut sc = Worker::new(&server, &client);

        while cs.run() && sc.run() {}

        eprintln!("{} thread done", id);
    });
}
