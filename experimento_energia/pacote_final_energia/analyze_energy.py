#!/usr/bin/env python3
"""
analyze_energy.py — Correlaciona captura de potência (ESP32) com
janelas de cifragem (Pi) e calcula energia por byte cifrado.

Uso:
    python3 analyze_energy.py <captura.csv> <janelas.csv>

Saída:
    energia_resultado.csv   — estatísticas por algoritmo
    energia_bruto.csv       — dados brutos por janela

Metodologia:
    - Potência média dentro de cada janela (sync=1) é extraída
      da captura da ESP32 usando os timestamps unix da Pi como
      referência de janela (com tolerância de ±MARGEM_US).
    - A baseline ociosa é estimada a partir das amostras com sync=0
      entre janelas (períodos de PAUSA_ENTRE_JANELAS do script da Pi).
    - Energia atribuível à cifragem = (P_janela - P_baseline) × duração
    - Energia por byte = energia_total / bytes_cifrados_na_janela
"""

import csv
import sys
import math
import statistics
from collections import defaultdict
from datetime import datetime

VOLUME_POR_EXEC_BYTES = 1024 * 1024      # 1 MiB por execução
MARGEM_US             = 500_000          # 0.5 s de margem nos timestamps


# ── Leitura de arquivos ───────────────────────────────────────────────────────

def carrega_captura(path):
    amostras = []
    with open(path) as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or linha.startswith("timestamp"):
                continue
            campos = linha.split(",")
            if len(campos) < 5:
                continue
            try:
                amostras.append((
                    int(campos[0]),     # timestamp_us (ESP32, micros())
                    float(campos[3]),   # power_mW
                    int(campos[4]),     # sync_pin
                ))
            except ValueError:
                continue
    return amostras


def carrega_janelas(path):
    janelas = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            janelas.append(row)
    return janelas


# ── Correlação de timestamps ──────────────────────────────────────────────────
# Os timestamps da ESP32 (micros()) e da Pi (time.time()) não são sincronizados.
# Usamos os períodos de sync=1 detectados na captura da ESP32 para fazer a
# correlação: a N-ésima janela sync=1 na captura corresponde à N-ésima
# entrada do arquivo de janelas da Pi.

def detecta_janelas_sync(amostras):
    """Retorna lista de (ts_inicio_us, ts_fim_us, [power_mW]) por janela sync=1."""
    janelas = []
    inicio  = None
    potencias = []

    for ts, pw, sync in amostras:
        if sync == 1:
            if inicio is None:
                inicio = ts
                potencias = []
            potencias.append(pw)
        else:
            if inicio is not None:
                janelas.append((inicio, ts, potencias[:]))
                inicio = None
                potencias = []

    return janelas


def estima_baseline(amostras):
    """Potência média nos períodos com sync=0 (Pi ociosa entre janelas)."""
    valores = [pw for _, pw, sync in amostras if sync == 0]
    if not valores:
        return None
    # Remove outliers grosseiros (>3σ) antes de calcular baseline
    m  = statistics.mean(valores)
    sd = statistics.stdev(valores) if len(valores) > 1 else 0
    limpos = [v for v in valores if abs(v - m) <= 3 * sd] if sd > 0 else valores
    return statistics.mean(limpos)


# ── Cálculo de energia ────────────────────────────────────────────────────────

def calcula_energia(janelas_sync, janelas_meta, baseline_mW):
    resultados = []

    n_corr = min(len(janelas_sync), len(janelas_meta))
    if len(janelas_sync) != len(janelas_meta):
        print(f"  ⚠ {len(janelas_sync)} janelas na captura vs "
              f"{len(janelas_meta)} no arquivo de janelas. "
              f"Usando as {n_corr} primeiras.")

    for i in range(n_corr):
        ts_ini, ts_fim, potencias = janelas_sync[i]
        meta = janelas_meta[i]

        if not potencias:
            continue

        p_media_mW  = statistics.mean(potencias)
        p_cifra_mW  = p_media_mW - baseline_mW
        dur_s       = (ts_fim - ts_ini) / 1e6
        n_exec      = int(meta["exec_por_janela"])
        bytes_total = n_exec * VOLUME_POR_EXEC_BYTES

        energia_mJ       = p_cifra_mW * dur_s
        energia_nJ_byte  = (energia_mJ * 1e6) / bytes_total if bytes_total > 0 else 0

        resultados.append({
            "algoritmo":        meta["algoritmo"],
            "p_total_mW":       p_media_mW,
            "p_cifra_mW":       p_cifra_mW,
            "dur_s":            dur_s,
            "energia_mJ":       energia_mJ,
            "energia_nJ_byte":  energia_nJ_byte,
            "n_amostras_esp32": len(potencias),
        })

    return resultados


# ── Estatísticas finais ───────────────────────────────────────────────────────

def sumariza(resultados):
    por_alg = defaultdict(list)
    for r in resultados:
        por_alg[r["algoritmo"]].append(r)

    resumo = []
    for alg, dados in sorted(por_alg.items()):
        n     = len(dados)
        p_tot = statistics.mean([d["p_total_mW"]      for d in dados])
        p_alg = statistics.mean([d["p_cifra_mW"]      for d in dados])
        e_val = [d["energia_nJ_byte"] for d in dados]
        e_med = statistics.mean(e_val)
        e_dp  = statistics.stdev(e_val) if n > 1 else 0
        e_ic  = 2.045 * e_dp / math.sqrt(n) if n > 1 else 0   # t(0.95, df=29)
        resumo.append({
            "algoritmo":          alg,
            "n":                  n,
            "p_total_mW_med":     round(p_tot, 2),
            "p_cifra_mW_med":     round(p_alg, 2),
            "energia_nJ_byte_med":round(e_med, 4),
            "energia_nJ_byte_dp": round(e_dp,  4),
            "IC95_nJ_byte":       round(e_ic,  4),
        })
    return resumo


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 analyze_energy.py <captura.csv> <janelas.csv>")
        sys.exit(1)

    cap_path, jan_path = sys.argv[1], sys.argv[2]

    print(f"Carregando captura:  {cap_path}")
    amostras = carrega_captura(cap_path)
    print(f"  {len(amostras)} amostras")

    print(f"Carregando janelas:  {jan_path}")
    janelas_meta = carrega_janelas(jan_path)
    print(f"  {len(janelas_meta)} janelas de metadados")

    print("\nEstimando baseline (Pi ociosa entre janelas)...")
    baseline = estima_baseline(amostras)
    if baseline is None:
        print("  ERRO: sem amostras com sync=0. Impossível estimar baseline.")
        sys.exit(1)
    print(f"  Potência baseline: {baseline:.1f} mW")

    print("\nDetectando janelas de cifragem na captura...")
    janelas_sync = detecta_janelas_sync(amostras)
    print(f"  {len(janelas_sync)} janelas detectadas (sync=1)")

    print("\nCalculando energia por byte...")
    resultados = calcula_energia(janelas_sync, janelas_meta, baseline)

    # Salva brutos
    bruto_path = "energia_bruto.csv"
    with open(bruto_path, "w", newline="") as f:
        campos = ["algoritmo", "p_total_mW", "p_cifra_mW",
                  "dur_s", "energia_mJ", "energia_nJ_byte", "n_amostras_esp32"]
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(resultados)
    print(f"  Dados brutos: {bruto_path}")

    # Salva resumo
    resumo = sumariza(resultados)
    resumo_path = "energia_resultado.csv"
    with open(resumo_path, "w", newline="") as f:
        campos = ["algoritmo", "n", "p_total_mW_med", "p_cifra_mW_med",
                  "energia_nJ_byte_med", "energia_nJ_byte_dp", "IC95_nJ_byte"]
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(resumo)

    print(f"\n{'─'*65}")
    print(f"{'Cifra':<10} {'P_total':>10} {'P_algo':>10} "
          f"{'E/byte':>12} {'IC95':>12}  n")
    print(f"{'':10} {'(mW)':>10} {'(mW)':>10} "
          f"{'(nJ/byte)':>12} {'(nJ/byte)':>12}")
    print(f"{'─'*65}")
    for r in resumo:
        print(f"  {r['algoritmo']:<10} "
              f"{r['p_total_mW_med']:>8.1f}   "
              f"{r['p_cifra_mW_med']:>8.1f}   "
              f"{r['energia_nJ_byte_med']:>10.4f}   "
              f"±{r['IC95_nJ_byte']:<9.4f}  "
              f"{r['n']}")
    print(f"{'─'*65}")
    print(f"\nResultado salvo em: {resumo_path}")

if __name__ == "__main__":
    main()
