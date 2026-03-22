#!/usr/bin/env python3
"""Diagnostic serial-to-TCP bridge with HDLC/RNS packet decoding.

Like serial_bridge.py, bidirectionally pipes raw bytes between a serial
port and TCP clients — but also taps both directions with HDLC decoders
and logs every decoded RNS packet to stderr with timestamps, direction,
packet type, dest hash, and context.

ESP32 <--serial/HDLC--> serial_bridge_diag <--TCP/HDLC--> Python RNS

Usage:
    python serial_bridge_diag.py --serial-port /dev/ttyUSB0 --tcp-port 4280

    # Or from a test via interop_helpers.start_diag_serial_bridge()

Packet decode logic is imported from rns_proxy.py.
"""

import argparse
import select
import serial as pyserial
import socket
import sys
import threading
import time

from rns_proxy import HdlcDecoder, parse_packet, format_packet


def _log(msg):
    """Write diagnostic output to stderr (does not interfere with tests)."""
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def serial_to_tcp(ser, client_sock, stop_event, decoder):
    """Forward bytes from serial to TCP, decoding HDLC frames."""
    while not stop_event.is_set():
        try:
            data = ser.read(1024)
            if data:
                # Forward transparently
                try:
                    client_sock.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break

                # Decode and log
                frames = decoder.feed(data)
                for frame in frames:
                    info = parse_packet(frame)
                    _log(format_packet("ESP32 -> TCP", info))
        except (pyserial.SerialException, OSError):
            break


def tcp_to_serial(client_sock, ser, stop_event, decoder):
    """Forward bytes from TCP to serial, decoding HDLC frames."""
    while not stop_event.is_set():
        try:
            ready, _, _ = select.select([client_sock], [], [], 0.1)
            if ready:
                data = client_sock.recv(4096)
                if not data:
                    break
                # Forward transparently
                ser.write(data)
                ser.flush()

                # Decode and log
                frames = decoder.feed(data)
                for frame in frames:
                    info = parse_packet(frame)
                    _log(format_packet("TCP -> ESP32", info))
        except (ConnectionResetError, OSError):
            break


def main():
    parser = argparse.ArgumentParser(description="Diagnostic serial-to-TCP bridge")
    parser.add_argument("--serial-port", default="/dev/ttyUSB0",
                        help="Serial port (default: /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--tcp-port", type=int, default=4280,
                        help="TCP server port (default: 4280)")
    args = parser.parse_args()

    # Open serial port without toggling DTR (would reset ESP32)
    ser = pyserial.Serial()
    ser.port = args.serial_port
    ser.baudrate = args.baud
    ser.timeout = 0.5
    ser.dsrdtr = False
    ser.rtscts = False
    ser.open()
    ser.dtr = False
    _log(f"[diag-bridge] serial: {args.serial_port} @ {args.baud}")
    print(f"[bridge] serial: {args.serial_port} @ {args.baud}")

    # Drain any pending boot output / stale HDLC data
    time.sleep(0.5)
    while ser.read(1024):
        pass

    # Start TCP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.tcp_port))
    server.listen(1)
    server.settimeout(1.0)
    _log(f"[diag-bridge] TCP listening on 127.0.0.1:{args.tcp_port}")
    print(f"[bridge] TCP listening on 127.0.0.1:{args.tcp_port}")
    sys.stdout.flush()

    try:
        while True:
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue

            _log(f"[diag-bridge] client connected from {addr}")
            print(f"[bridge] client connected from {addr}")
            sys.stdout.flush()

            stop = threading.Event()
            serial_decoder = HdlcDecoder()
            tcp_decoder = HdlcDecoder()

            t1 = threading.Thread(
                target=serial_to_tcp,
                args=(ser, client, stop, serial_decoder),
                daemon=True,
            )
            t2 = threading.Thread(
                target=tcp_to_serial,
                args=(client, ser, stop, tcp_decoder),
                daemon=True,
            )
            t1.start()
            t2.start()

            # Wait for either thread to finish
            t1.join()
            stop.set()
            t2.join(timeout=2)

            try:
                client.close()
            except Exception:
                pass
            _log("[diag-bridge] client disconnected")
            print("[bridge] client disconnected")
            sys.stdout.flush()

    except KeyboardInterrupt:
        _log("\n[diag-bridge] shutting down")
    finally:
        ser.close()
        server.close()


if __name__ == "__main__":
    main()
