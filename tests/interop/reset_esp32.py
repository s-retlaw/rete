#!/usr/bin/env python3
"""Reset ESP32 via DTR toggle on serial port."""
import sys
import time
import serial

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
s = serial.Serial(port, 115200)
s.dtr = False
time.sleep(0.1)
s.dtr = True
time.sleep(0.1)
s.dtr = False
s.close()
