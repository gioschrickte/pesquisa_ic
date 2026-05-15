#!/usr/bin/env python3
"""
capture.py — Captura serial da ESP32 e grava CSV.

Uso:
    python3 capture.py <porta> <arquivo_saida>

Exemplos:
    Linux:   python3 capture.py /dev/ttyUSB0 captura.csv
    Windows: python3 capture.py COM3 captura.csv

Instalar dependência:
    pip install pyserial

Encerre com Ctrl+C ao fim do experimento.
"""

import serial
import sys
import time
from datetime import datetime

PORT     = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
OUTFILE  = sys.argv[2] if len(sys.argv) > 2 else \
           f"captura_{datetime.now():%Y%m%d_%H%M%S}.csv"
BAUD     = 921600

print(f"Porta:  {PORT}")
print(f"Saída:  {OUTFILE}")
print(f"Baud:   {BAUD}")
print("Ctrl+C para encerrar\n")

try:
    ser = serial.Serial(PORT, BAUD, timeout=2)
except serial.SerialException as e:
    print(f"ERRO ao abrir porta: {e}")
    sys.exit(1)

time.sleep(2)           # aguarda ESP32 reiniciar após abertura da porta
ser.reset_input_buffer()

t0      = time.time()
samples = 0

try:
    with open(OUTFILE, "w", buffering=1) as f:
        while True:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            f.write(line + "\n")

            if not line.startswith("#") and not line.startswith("timestamp"):
                samples += 1
                if samples % 500 == 0:
                    elapsed = time.time() - t0
                    rate    = samples / elapsed if elapsed > 0 else 0
                    print(f"\r{samples:6d} amostras | "
                          f"{elapsed:6.1f}s | {rate:5.0f} Hz    ", end="")

except KeyboardInterrupt:
    elapsed = time.time() - t0
    print(f"\n\nEncerrado: {samples} amostras em {elapsed:.1f}s")
    print(f"Arquivo salvo: {OUTFILE}")
finally:
    ser.close()
