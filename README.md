# Benchmark IC — Cifras Leves para IIoT

Implementações de referência das 4 cifras de fluxo, padronizadas
para benchmark comparativo em ARM Cortex-A72 (Raspberry Pi 4).

## Origem das implementações

Todas as cifras usam a implementação de referência publicada pelo
designer ou pelo comitê de padronização correspondente:

| Cifra      | Fonte                                                          |
|------------|----------------------------------------------------------------|
| ChaCha20   | D. J. Bernstein, eSTREAM submission (`chacha-merged.c`, 2008)  |
| Enocoro    | Hitachi Systems Development Lab. (Rev. 1.0, 2010-02-02)         |
| Rabbit     | Cryptico A/S, eSTREAM submission                                |
| Trivium    | C. De Cannière, K.U.Leuven (eSTREAM submission)                 |

### Notas sobre o Trivium

A implementação foi obtida do mirror `crocs-muni/CryptoStreams`,
que mantém o código de referência envelopado em `namespace` C++ para
seu framework. Esse envelope foi removido mecanicamente para uso
direto em C, sem alteração do conteúdo algorítmico (macros UPDATE/
ROTATE/LOAD/STORE, função TRIVIUM_process_bytes, keysetup e ivsetup
preservados byte-a-byte).

A correção da implementação foi validada contra o test vector oficial
"Set 1, vector # 0" do eSTREAM (chave 0x80...0, IV 0x0...0): os
primeiros 16 bytes de keystream produzidos correspondem exatamente
aos esperados (`38EB86FF730D7A9CAF8DF13A4420540D`).

O número de rodadas de inicialização foi fixado em 9 (valor canônico
da especificação do De Cannière, correspondendo a 1152 passos de
clock) — o framework do CRoCS parametriza esse valor para análises
round-reduced, o que não se aplica a este trabalho.

### Notas sobre o Enocoro

A interface da Hitachi (`ENOCORO_init` + `ENOCORO_keystream`) difere
da interface eSTREAM adotada pelas outras três cifras: requer XOR
manual após geração de keystream. O harness de medição reflete
isso, e a operação medida permanece equivalente (cifra 1 MiB).

## Estrutura

```
chacha20/   main.c, chacha.c, ecrypt-{sync,portable,machine,config}.h
enocoro/    main.c, enocoro.c, enocoro.h
rabbit/     main.c, rabbit.c, ecrypt-{sync,portable,machine,config}.h
trivium/    main.c, trivium.c, trivium.h, ecrypt-{portable,machine,config}.h
```

## Compilação

Cada cifra é independente. De dentro de cada diretório:

```bash
gcc -O3 -std=c99 main.c <impl>.c -o <cifra>
```

Ou com o nome correto da implementação:

```bash
cd chacha20 && gcc -O3 -std=c99 main.c chacha.c -o chacha20
cd enocoro  && gcc -O3 -std=c99 main.c enocoro.c -o enocoro
cd rabbit   && gcc -O3 -std=c99 main.c rabbit.c -o rabbit
cd trivium  && gcc -O3 -std=c99 main.c trivium.c -o trivium
```

## Operação medida (idêntica em todas as cifras)

1. Setup de chave e IV (zerados — conteúdo é irrelevante para tempo
   de cifra, que não depende dos dados em cifras de fluxo bem
   projetadas)
2. Loop de 1024 iterações cifrando chunks de 1024 bytes (= 1 MiB)
3. Tempo medido com `CLOCK_PROCESS_CPUTIME_ID` (tempo de CPU em modo
   usuário do processo, isolado de IO e scheduler)
4. Saída: tempo em segundos com 9 dígitos de precisão (formato
   `%.9f\n`) no `stdout`

## Notas técnicas

- **Alinhamento:** os buffers `buf_in` e `buf_out` são declarados com
  `__attribute__((aligned(16)))` para evitar SIGBUS em ARM ao acessar
  memória via `m64*` no Trivium.
- **Endianness:** `ecrypt-config.h` define `ECRYPT_LITTLE_ENDIAN` para
  `__aarch64__` (Raspberry Pi 4). Confirmado em runtime.
- **MMX:** o Trivium tem dois caminhos de execução. Em x86 com MMX,
  usa `__m64` intrinsics. Em ARM, cai automaticamente no caminho
  escalar `typedef u64 m64`. Ambos produzem o mesmo output.
- **Renomeação no Trivium:** as funções foram renomeadas de
  `ECRYPT_*` para `TRIVIUM_*` para evitar conflito de símbolos caso
  múltiplas cifras eSTREAM sejam linkadas no mesmo binário.

## Validação

Cada implementação foi validada antes do benchmarking:
- Trivium: test vector oficial Set 1, vector # 0 — passou.
- ChaCha20: determinismo entre runs — confirmado.
- Rabbit: determinismo entre runs — confirmado.
- Enocoro: determinismo entre runs — confirmado.
