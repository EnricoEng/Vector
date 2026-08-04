# ProjetoTestPython — caso controlado de projeto com vários arquivos

Projeto em Python usado para validar a análise de uma **pasta inteira**, e não de um arquivo isolado.

A estrutura reproduz deliberadamente a de [ProjetoTestC](../ProjetoTestC), com os mesmos nomes de função e o mesmo caminho. Isso permite comparar diretamente o analisador de Python, baseado no módulo `ast`, com o de C, baseado no `tree-sitter`: os dois devem produzir o mesmo caminho.

A função vulnerável está em `src/executor.py`, enquanto o ponto de entrada está em `src/main.py`.

## Caminho esperado

```text
main -> server_start -> router_dispatch -> handler_execute -> run_command -> vulnerable_function
```

| Função | Arquivo |
|---|---|
| `main` | `src/main.py` |
| `server_start` | `src/server.py` |
| `router_dispatch` | `src/router.py` |
| `handler_execute` | `src/handler.py` |
| `run_command` | `src/executor.py` |
| `vulnerable_function` | `src/executor.py` |

## Funções fora do caminho

- `log_init`, `log_info`, `log_error` e `write_line` em `src/logger.py`;
- `read_request` em `src/server.py`;
- `handle_unknown` em `src/router.py`;
- `parse_payload` e `payload_is_empty` em `src/handler.py`.

## Como executar a análise

```bash
python analyzer.py \
  --source cases/ProjetoTestPython \
  --cves data_cves/caseProjetoTestPython.json \
  --entry main \
  --product projeto-teste-python \
  --version 1.0.0 \
  --output results/projeto-teste-python-vex.json \
  --manual
```

Resultado esperado com as respostas `s` para entrada controlada e `n` para mitigação:

```text
AFFECTED
```

## Como executar o programa

```bash
python cases/ProjetoTestPython/src/main.py
```

Assim como no projeto em C, a requisição precisa começar com `RUN ` para chegar à função vulnerável:

```text
RUN 2 + 2
```

Encerre com `Ctrl+D` (Linux e macOS) ou `Ctrl+Z` seguido de Enter (Windows).

> A `vulnerable_function` entrega o texto recebido ao `eval()`, sem validação. Use apenas expressões inofensivas, como no exemplo acima.
