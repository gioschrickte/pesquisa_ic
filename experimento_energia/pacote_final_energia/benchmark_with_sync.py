#!/usr/bin/env python3
"""
benchmark_with_sync.py — Roda as cifras na Pi com sinalização GPIO
para sincronização com a captura de energia da ESP32.

Cada "janela de medição" executa o binário N vezes em sequência
com GPIO 17 em nível alto, permitindo que a ESP32 identifique
o período exato de cifragem nas amostras de potência.

Uso (na Pi, via SSH ou terminal local):
    sudo python3 benchmark_with_sync.py

Requer sudo para controle de GPIO via sysfs.

Saída: janelas_energia_<timestamp>.csv
"""

import subprocess
import csv
import time
import random
import os
from pathlib import Path
from datetime import datetime

# ── Configuração ──────────────────────────────────────────────────────────────
ALGORITMOS          = ["./chacha20", "./enocoro", "./rabbit", "./trivium"]
NUM_JANELAS         = 30       # janelas de medição por algoritmo
EXEC_POR_JANELA     = 50       # execuções dentro de cada janela (~1 s por janela p/ cifras rápidas)
TIMEOUT_S           = 120      # timeout por execução individual
SYNC_GPIO           = 17       # GPIO da Pi que sinaliza para a ESP32
PAUSA_ENTRE_JANELAS = 3        # segundos de idle entre janelas (captura baseline)
SEED                = 42
# ─────────────────────────────────────────────────────────────────────────────

GPIO_BASE = Path("/sys/class/gpio")

def gpio_setup():
    export = GPIO_BASE / "export"
    gpio_dir = GPIO_BASE / f"gpio{SYNC_GPIO}"
    if not gpio_dir.exists():
        export.write_text(str(SYNC_GPIO))
        time.sleep(0.15)
    (gpio_dir / "direction").write_text("out")
    (gpio_dir / "value").write_text("0")

def gpio_set(val: int):
    (GPIO_BASE / f"gpio{SYNC_GPIO}" / "value").write_text(str(val))

def gpio_cleanup():
    try:
        (GPIO_BASE / "unexport").write_text(str(SYNC_GPIO))
    except Exception:
        pass

def verificar_binarios():
    faltando = [a for a in ALGORITMOS if not Path(a).is_file()]
    if faltando:
        print(f"ERRO: binários não encontrados: {faltando}")
        print("Execute este script no mesmo diretório dos binários.")
        raise SystemExit(1)

def executar_janela(binario: str, n: int):
    """Executa o binário n vezes e retorna lista de tempos (s)."""
    tempos = []
    for _ in range(n):
        try:
            r = subprocess.run(
                [binario], capture_output=True, text=True, timeout=TIMEOUT_S
            )
            if r.returncode == 0 and r.stdout.strip():
                tempos.append(float(r.stdout.strip()))
        except (subprocess.TimeoutExpired, ValueError):
            pass
    return tempos

def main():
    if os.geteuid() != 0:
        print("ERRO: execute com sudo (necessário para GPIO sysfs).")
        raise SystemExit(1)

    verificar_binarios()
    gpio_setup()

    # Warm-up (5 execuções por algoritmo, descartadas)
    print("Warm-up...")
    for alg in ALGORITMOS:
        for _ in range(5):
            subprocess.run([alg], capture_output=True, timeout=TIMEOUT_S)
    print("  ok\n")

    # Plano intercalado aleatório
    rng  = random.Random(SEED)
    plano = [(alg, i) for alg in ALGORITMOS for i in range(NUM_JANELAS)]
    rng.shuffle(plano)
    total = len(plano)

    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"janelas_energia_{ts}.csv"

    print(f"Executando {total} janelas ({NUM_JANELAS} por cifra × {len(ALGORITMOS)} cifras)")
    print(f"Cada janela: {EXEC_POR_JANELA} cifragens com GPIO{SYNC_GPIO}=HIGH")
    print(f"Saída: {out}\n")

    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "janela_idx", "algoritmo", "exec_por_janela",
            "t_inicio_unix_us", "t_fim_unix_us", "duracao_janela_s",
            "n_validos", "tempo_medio_ms", "tempo_dp_ms",
        ])

        for idx, (alg, _) in enumerate(plano, 1):
            time.sleep(PAUSA_ENTRE_JANELAS)   # idle → captura baseline entre janelas

            t0_us = int(time.time() * 1_000_000)
            gpio_set(1)                        # ← ESP32 começa a marcar

            tempos = executar_janela(alg, EXEC_POR_JANELA)

            gpio_set(0)                        # ← ESP32 para de marcar
            t1_us = int(time.time() * 1_000_000)

            dur    = (t1_us - t0_us) / 1e6
            nome   = Path(alg).name
            n_val  = len(tempos)
            t_med  = (sum(tempos) / n_val * 1000) if n_val else 0
            import statistics
            t_dp   = (statistics.stdev(tempos) * 1000) if n_val > 1 else 0

            w.writerow([idx, nome, EXEC_POR_JANELA,
                        t0_us, t1_us, f"{dur:.3f}",
                        n_val, f"{t_med:.4f}", f"{t_dp:.4f}"])
            f.flush()

            print(f"  [{idx:3d}/{total}] {nome:<10}  "
                  f"janela={dur:.1f}s  t_med={t_med:.3f}ms  "
                  f"válidos={n_val}/{EXEC_POR_JANELA}")

    gpio_cleanup()
    print(f"\nConcluído. Arquivo: {out}")
    print("Agora rode analyze_energy.py no PC com captura.csv e este arquivo.")

if __name__ == "__main__":
    main()
