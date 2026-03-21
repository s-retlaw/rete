#!/usr/bin/env python3
"""Transparent serial-to-TCP byte bridge for ESP32-C6 testing.

Bidirectionally pipes raw bytes between a serial port and TCP clients.
Both ESP32 (HDLC over UART) and Python RNS (HDLC over TCP) use the same
framing — no translation needed, just byte forwarding.

ESP32 <--serial/HDLC--> serial_bridge <--TCP/HDLC--> Python RNS

Usage:
    python serial_bridge.py --serial-port /dev/ttyUSB0 --tcp-port 4280

The bridge accepts one TCP client at a time. When the client disconnects,
it waits for a new connection.
"""

import argparse
import select
import serial as pyserial
import socket
import sys
import threading
import time


def serial_to_tcp(ser, client_sock, stop_event):
    """Forward bytes from serial to TCP."""
    while not stop_event.is_set():
        try:
            data = ser.read(1024)
            if data:
                try:
                    client_sock.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except (pyserial.SerialException, OSError):
            break


def tcp_to_serial(client_sock, ser, stop_event):
    """Forward bytes from TCP to serial."""
    while not stop_event.is_set():
        try:
            ready, _, _ = select.select([client_sock], [], [], 0.1)
            if ready:
                data = client_sock.recv(4096)
                if not data:
                    break
                ser.write(data)
                ser.flush()
        except (ConnectionResetError, OSError):
            break


def main():
    parser = argparse.ArgumentParser(description="Serial-to-TCP byte bridge")
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
    print(f"[bridge] TCP listening on 127.0.0.1:{args.tcp_port}")
    sys.stdout.flush()

    try:
        while True:
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue

            print(f"[bridge] client connected from {addr}")
            sys.stdout.flush()
            stop = threading.Event()

            t1 = threading.Thread(target=serial_to_tcp, args=(ser, client, stop),
                                  daemon=True)
            t2 = threading.Thread(target=tcp_to_serial, args=(client, ser, stop),
                                  daemon=True)
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
            print("[bridge] client disconnected")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[bridge] shutting down")
    finally:
        ser.close()
        server.close()


if __name__ == "__main__":
    main()
