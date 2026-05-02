#!/usr/bin/env python3
"""
Benchmark comparativo de algoritmos de criptografia leve.
Executa cada binário N vezes em ordem intercalada, com warm-up,
e gera CSVs com dados brutos e estatísticas.

Recomendações de execução (rodar antes do script):
    sudo cpupower frequency-set -g performance
    # Fechar processos não essenciais; conectar a Raspberry à fonte oficial.

Execução com afinidade de CPU (recomendado, fixa no core 3):
    taskset -c 3 python3 benchmark.py
"""

import subprocess
import csv
import statistics
import math
import random
import time
import sys
import platform
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
ALGORITMOS = ["./chacha20", "./enocoro", "./rabbit", "./trivium"]
RODADAS_VALIDAS = 50      # medições efetivamente registradas
RODADAS_WARMUP = 5        # descartadas (aquecem cache, branch predictor, TLB)
TIMEOUT_SEG = 60          # mata execução travada
SEED = 42                 # reprodutibilidade da ordem intercalada

OUT_BRUTOS = "tempos_brutos.csv"
OUT_RESUMO = "tempos_resumo.csv"
OUT_AMBIENTE = "ambiente.txt"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def nome_limpo(caminho: str) -> str:
    return Path(caminho).stem  # remove extensão .o e diretório


def verificar_executaveis(algoritmos):
    faltando = [a for a in algoritmos if not Path(a).is_file()]
    if faltando:
        print(f"❌ Executáveis não encontrados: {faltando}", file=sys.stderr)
        sys.exit(1)
    nao_executaveis = [a for a in algoritmos if not Path(a).stat().st_mode & 0o111]
    if nao_executaveis:
        print(f"❌ Sem permissão de execução: {nao_executaveis}", file=sys.stderr)
        sys.exit(1)


def coletar_ambiente() -> str:
    """Registra estado do sistema para reprodutibilidade — vai no artigo."""
    linhas = [
        f"Data/hora: {datetime.now().isoformat()}",
        f"Hostname:  {platform.node()}",
        f"Kernel:    {platform.platform()}",
        f"Python:    {sys.version.split()[0]}",
    ]

    def tenta(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except Exception:
            return "n/d"

    linhas.append("\n--- CPU ---")
    linhas.append(tenta(["lscpu"]))
    linhas.append("\n--- Governor ---")
    linhas.append(tenta(["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"]))
    linhas.append("\n--- Frequência atual (kHz) ---")
    linhas.append(tenta(["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"]))
    linhas.append("\n--- Temperatura (m°C) ---")
    linhas.append(tenta(["cat", "/sys/class/thermal/thermal_zone0/temp"]))
    linhas.append("\n--- GCC ---")
    linhas.append(tenta(["gcc", "--version"]))

    return "\n".join(linhas)


def executar_uma_vez(binario: str):
    """
    Retorna (tempo: float | None, erro: str | None).
    Captura falhas sem derrubar o experimento.
    """
    try:
        r = subprocess.run(
            [binario],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEG,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception as e:
        return None, f"exception:{e}"

    if r.returncode != 0:
        return None, f"returncode={r.returncode}"

    saida = r.stdout.strip()
    if not saida:
        return None, "stdout_vazio"

    try:
        return float(saida), None
    except ValueError:
        return None, f"nao_numerico:'{saida[:40]}'"


# ---------------------------------------------------------------------------
# Estatística
# ---------------------------------------------------------------------------
# Valores críticos da distribuição t de Student para IC 95% bicaudal.
# Para n=30 → df=29 → t=2.045; n=50 → df=49 → t=2.010.
T_CRITICO_95 = {
    9: 2.262, 14: 2.145, 19: 2.093, 24: 2.064, 29: 2.045,
    39: 2.023, 49: 2.010, 59: 2.001, 99: 1.984,
}


def t_critico(n: int) -> float:
    df = n - 1
    if df in T_CRITICO_95:
        return T_CRITICO_95[df]
    chaves = sorted(T_CRITICO_95.keys())
    if df < chaves[0]:
        return T_CRITICO_95[chaves[0]]
    if df > chaves[-1]:
        return 1.96  # converge para z
    for i in range(len(chaves) - 1):
        if chaves[i] <= df <= chaves[i + 1]:
            x0, x1 = chaves[i], chaves[i + 1]
            y0, y1 = T_CRITICO_95[x0], T_CRITICO_95[x1]
            return y0 + (y1 - y0) * (df - x0) / (x1 - x0)
    return 1.96


def estatisticas(tempos):
    validos = [t for t in tempos if t is not None]
    n = len(validos)
    if n == 0:
        return dict(n=0, media=None, mediana=None, minimo=None, maximo=None,
                    desvio=None, ic95=None, cv_pct=None)
    media = statistics.mean(validos)
    desvio = statistics.stdev(validos) if n > 1 else 0.0
    erro_padrao = desvio / math.sqrt(n) if n > 1 else 0.0
    ic95 = t_critico(n) * erro_padrao
    cv_pct = (desvio / media * 100) if media > 0 else 0.0
    return dict(
        n=n,
        media=media,
        mediana=statistics.median(validos),
        minimo=min(validos),
        maximo=max(validos),
        desvio=desvio,
        ic95=ic95,
        cv_pct=cv_pct,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def main():
    verificar_executaveis(ALGORITMOS)

    Path(OUT_AMBIENTE).write_text(coletar_ambiente())
    print(f"📝 Ambiente registrado em {OUT_AMBIENTE}\n")

    dados = {alg: [None] * RODADAS_VALIDAS for alg in ALGORITMOS}
    erros = {alg: [] for alg in ALGORITMOS}

    # ---- WARM-UP ----
    print(f"🔥 Warm-up: {RODADAS_WARMUP} execuções por algoritmo (descartadas)")
    for alg in ALGORITMOS:
        for _ in range(RODADAS_WARMUP):
            executar_uma_vez(alg)
    print("   ok\n")

    # ---- ORDEM INTERCALADA ----
    # Embaralhamos pares (algoritmo, índice_da_rodada). Assim, drift térmico
    # e ruído de scheduler se distribuem uniformemente entre algoritmos,
    # em vez de penalizar quem é executado por último.
    rng = random.Random(SEED)
    plano = [(alg, i) for alg in ALGORITMOS for i in range(RODADAS_VALIDAS)]
    rng.shuffle(plano)

    total = len(plano)
    t0 = time.time()
    print(f"🚀 Executando {total} medições intercaladas (seed={SEED})...")

    for idx, (alg, i_rodada) in enumerate(plano, start=1):
        tempo, erro = executar_uma_vez(alg)
        if tempo is not None:
            dados[alg][i_rodada] = tempo
        else:
            erros[alg].append((i_rodada + 1, erro))

        if idx % 25 == 0 or idx == total:
            elapsed = time.time() - t0
            print(f"   [{idx:4d}/{total}]  {elapsed:6.1f}s decorridos")

    print()

    # ---- ESTATÍSTICAS ----
    print("📊 Estatísticas:\n")
    resumo = []
    for alg in ALGORITMOS:
        s = estatisticas(dados[alg])
        nome = nome_limpo(alg)
        resumo.append({
            "Algoritmo": nome,
            "N_validas": s["n"],
            "N_falhas": RODADAS_VALIDAS - s["n"],
            "Media_s": s["media"],
            "Mediana_s": s["mediana"],
            "Min_s": s["minimo"],
            "Max_s": s["maximo"],
            "DesvioPadrao_s": s["desvio"],
            "IC95_s": s["ic95"],
            "CV_percent": s["cv_pct"],
        })
        if s["n"] > 0:
            print(f"  {nome:10s}  média={s['media']:.6f}s  "
                  f"σ={s['desvio']:.6f}s  CV={s['cv_pct']:.2f}%  "
                  f"IC95=±{s['ic95']:.6f}s  (n={s['n']})")
        else:
            print(f"  {nome:10s}  ❌ todas as execuções falharam")
        if erros[alg]:
            print(f"     ⚠️  {len(erros[alg])} falha(s): "
                  f"{erros[alg][:3]}{'...' if len(erros[alg]) > 3 else ''}")

    # ---- CSV BRUTOS ----
    print(f"\n💾 Gravando {OUT_BRUTOS}...")
    with open(OUT_BRUTOS, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Rodada"] + [nome_limpo(a) for a in ALGORITMOS])
        for i in range(RODADAS_VALIDAS):
            linha = [i + 1]
            for alg in ALGORITMOS:
                v = dados[alg][i]
                linha.append("" if v is None else f"{v:.9f}")
            w.writerow(linha)

    # ---- CSV RESUMO ----
    print(f"💾 Gravando {OUT_RESUMO}...")
    with open(OUT_RESUMO, "w", newline="") as f:
        cols = ["Algoritmo", "N_validas", "N_falhas", "Media_s", "Mediana_s",
                "Min_s", "Max_s", "DesvioPadrao_s", "IC95_s", "CV_percent"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for linha in resumo:
            w.writerow(linha)

    print("\n✅ Concluído.")


if __name__ == "__main__":
    main()