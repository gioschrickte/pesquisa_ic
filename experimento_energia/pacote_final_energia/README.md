# Experimento de Medição de Energia — Guia de Operação
## IC: Avaliação Comparativa de Cifras de Fluxo Leves

---

## Hardware necessário

- Raspberry Pi 4 (com os 4 binários já compilados)
- Módulo INA219
- ESP32 DevKit
- Fonte de bancada ajustável
- PC com Arduino IDE e Python 3

---

## Conexões físicas

### INA219 ↔ Fonte de bancada / Pi (alimentação)

```
Fonte bancada (+) → fio vermelho descascado → Vin+ do INA219
                                               Vin− do INA219 → Pino 4 da Pi (+5V)
Fonte bancada (-) ─────────────────────────────────────────── → Pino 6 da Pi (GND)
```

**IMPORTANTE:** ajustar a fonte de bancada para **5.10 V** antes de ligar.
Confirmar com multímetro nos terminais antes de conectar a Pi.

### INA219 ↔ ESP32 (comunicação I2C)

| INA219 | ESP32     |
|--------|-----------|
| Vcc    | 3V3       |
| GND    | GND       |
| SDA    | GPIO 21   |
| SCL    | GPIO 22   |

### Pi ↔ ESP32 (sinal de sincronização)

| Pi                    | ESP32   |
|-----------------------|---------|
| GPIO 17 (pino fís. 11)| GPIO 4  |
| GND     (pino fís.  9)| GND     |

---

## Sequência de operação

### Passo 1 — Preparar a ESP32 (PC)

1. Abrir Arduino IDE
2. Instalar biblioteca: Tools → Manage Libraries → "Adafruit INA219"
3. Abrir `esp32_power_monitor.ino`
4. Selecionar placa: Tools → Board → ESP32 Dev Module
5. Selecionar porta: Tools → Port → (porta da ESP32)
6. Upload (Ctrl+U). Se travar em "Connecting...", pressionar BOOT na ESP32.
7. Abrir Serial Monitor a **921600 baud**
8. Deve aparecer: `# INA219 OK — aguardando dados`
   e depois linhas de CSV com bus ≈ 0V e current ≈ 0 mA (Vin+ solto ainda)

### Passo 2 — Ligar o circuito

1. Fechar o Serial Monitor (libera a porta para o capture.py)
2. Confirmar que a fonte está em 5.10 V (medir com multímetro)
3. Ligar a Pi pela fonte de bancada (via INA219 → pino 4 do GPIO)
4. Aguardar a Pi bootar completamente (LED verde estável)
5. Na Pi, verificar undervoltage:
   ```bash
   vcgencmd get_throttled
   ```
   Deve retornar `throttled=0x0`. Se não, aumentar a fonte para 5.15 V.

### Passo 3 — Captura de baseline (PC)

Com a Pi ociosa (sem processos pesados):

```bash
# Linux
python3 capture.py /dev/ttyUSB0 baseline.csv

# Windows
python3 capture.py COM3 baseline.csv
```

Aguardar **30 segundos** e Ctrl+C.

### Passo 4 — Rodar o benchmark (Pi, via SSH)

```bash
cd ~/diretorio_dos_binarios/
sudo python3 benchmark_with_sync.py
```

O script vai:
- Fazer warm-up (descartado)
- Executar 30 janelas por cifra em ordem intercalada
- Sinalizar início/fim de cada janela via GPIO 17
- Salvar `janelas_energia_<timestamp>.csv`

Duração estimada: 30–60 minutos.

### Passo 5 — Captura do experimento (PC, em paralelo com Passo 4)

Abrir outro terminal **antes** de rodar o benchmark:

```bash
python3 capture.py /dev/ttyUSB0 captura_experimento.csv
```

Deixar rodando durante todo o experimento. Ctrl+C só depois que o
benchmark terminar.

### Passo 6 — Análise (PC)

```bash
python3 analyze_energy.py captura_experimento.csv janelas_energia_*.csv
```

Gera:
- `energia_resultado.csv` — estatísticas por algoritmo (média, DP, IC95)
- `energia_bruto.csv` — dados brutos por janela

---

## O que fazer se algo der errado

| Sintoma | Causa provável | Solução |
|---------|---------------|---------|
| Pi não boota (LED piscando) | Tensão baixa | Aumentar fonte para 5.15 V |
| `vcgencmd get_throttled` ≠ 0x0 | Undervoltage | Aumentar fonte 50 mV |
| Serial Monitor mostra `????` | Baud rate errado | Setar para 921600 |
| `ERRO: INA219 nao detectado` | Fiação I2C | Verificar SDA/SCL (podem estar invertidos) |
| Corrente negativa no Serial | Vin+ e Vin− invertidos | Trocar os dois fios no borne |
| Janelas sync ≠ janelas meta | Captura não estava rodando | Reiniciar tudo do Passo 3 |

---

## Arquivos gerados

| Arquivo | Gerado por | Conteúdo |
|---------|-----------|---------|
| `baseline.csv` | capture.py | Potência da Pi ociosa (30s) |
| `captura_experimento.csv` | capture.py | Potência durante todo o benchmark |
| `janelas_energia_*.csv` | benchmark_with_sync.py | Timestamps e metadados de cada janela |
| `energia_bruto.csv` | analyze_energy.py | Energia por janela individual |
| `energia_resultado.csv` | analyze_energy.py | Estatísticas finais por algoritmo |
