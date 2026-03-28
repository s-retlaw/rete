//! Transparent serial-to-TCP byte bridge.
//!
//! Bidirectionally pipes raw bytes between a serial port and TCP clients.
//! No protocol awareness — just byte forwarding.
//!
//! Usage:
//!     rete-serial-bridge --serial-port /dev/ttyUSB0 --tcp-port 4280 [--baud 115200]

use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_serial::SerialPortBuilderExt;

fn parse_args() -> (String, u16, u32) {
    let mut args = std::env::args().skip(1);
    let mut serial_port = String::from("/dev/ttyUSB0");
    let mut tcp_port: u16 = 4280;
    let mut baud: u32 = 115200;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--serial-port" => serial_port = args.next().expect("missing --serial-port value"),
            "--tcp-port" => {
                tcp_port = args
                    .next()
                    .expect("missing --tcp-port value")
                    .parse()
                    .expect("invalid --tcp-port")
            }
            "--baud" => {
                baud = args
                    .next()
                    .expect("missing --baud value")
                    .parse()
                    .expect("invalid --baud")
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: rete-serial-bridge --serial-port /dev/ttyUSB0 --tcp-port 4280 [--baud 115200]"
                );
                process::exit(1);
            }
        }
    }
    (serial_port, tcp_port, baud)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (serial_port, tcp_port, baud) = parse_args();

    let serial = tokio_serial::new(&serial_port, baud).open_native_async()?;
    eprintln!("[bridge] serial: {serial_port} @ {baud}");

    let listener = TcpListener::bind(("127.0.0.1", tcp_port)).await?;
    eprintln!("[bridge] TCP listening on 127.0.0.1:{tcp_port}");

    let (ser_read, ser_write) = tokio::io::split(serial);
    let ser_read = std::sync::Arc::new(tokio::sync::Mutex::new(ser_read));
    let ser_write = std::sync::Arc::new(tokio::sync::Mutex::new(ser_write));

    loop {
        let (stream, addr) = listener.accept().await?;
        stream.set_nodelay(true)?;
        eprintln!("[bridge] client connected from {addr}");

        let (tcp_read, tcp_write) = tokio::io::split(stream);
        let sr = ser_read.clone();
        let sw = ser_write.clone();

        // serial -> tcp
        let mut s2t = tokio::spawn(async move {
            let mut sr = sr.lock().await;
            let mut tcp_write = tcp_write;
            let mut buf = [0u8; 4096];
            loop {
                match sr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tcp_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // tcp -> serial
        let mut t2s = tokio::spawn(async move {
            let mut sw = sw.lock().await;
            let mut tcp_read = tcp_read;
            let mut buf = [0u8; 4096];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for either direction to finish, then abort the other
        // to release the serial Mutex for the next client connection.
        tokio::select! {
            _ = &mut s2t => { t2s.abort(); }
            _ = &mut t2s => { s2t.abort(); }
        }
        eprintln!("[bridge] client disconnected");
    }
}
