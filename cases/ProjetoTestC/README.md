# ProjetoTestC — caso controlado de projeto com vários arquivos

Projeto em C usado para validar a análise de uma **pasta inteira**, e não de um arquivo isolado.

A função vulnerável está em `src/exec.c`, enquanto o ponto de entrada está em `src/main.c`. Nenhum arquivo sozinho contém o caminho completo: ele só existe quando os grafos de todos os arquivos são unidos.

## Caminho esperado

```text
main -> server_start -> router_dispatch -> handler_execute -> run_command -> vulnerable_function
```

Cada elo desse caminho está em um arquivo diferente:

| Função | Arquivo |
|---|---|
| `main` | `src/main.c` |
| `server_start` | `src/server.c` |
| `router_dispatch` | `src/router.c` |
| `handler_execute` | `src/handler.c` |
| `run_command` | `src/exec.c` |
| `vulnerable_function` | `src/exec.c` |

## Funções fora do caminho

Existem para que a busca em profundidade precise descartar ramos, em vez de encontrar o alvo trivialmente:

- `log_init`, `log_info`, `log_error` em `src/logger.c`;
- `read_request` em `src/server.c`;
- `handle_unknown` em `src/router.c`;
- `parse_payload` em `src/handler.c`;
- `payload_is_empty`, declarada como `static inline` em `include/handler.h`, para exercitar a leitura de definições dentro de cabeçalhos.

## Como executar

```bash
python analyzer.py \
  --source cases/ProjetoTestC \
  --cves data_cves/caseProjetoTestC.json \
  --entry main \
  --product projeto-teste-c \
  --version 1.0.0 \
  --output results/projeto-teste-c-vex.json \
  --manual
```

Resultado esperado com as respostas `s` para entrada controlada e `n` para mitigação:

```text
AFFECTED
```
