# Reachability Analysis PoC

Prova de conceito desenvolvida para avaliar se uma função associada a uma vulnerabilidade conhecida pode ser alcançada a partir de um ponto de entrada de uma aplicação Python.

O protótipo realiza uma análise estática simplificada do código-fonte, constrói um grafo de chamadas (*call graph*) e executa uma análise de alcançabilidade (*reachability analysis*). Quando a função vulnerável é classificada como alcançável, o programa solicita informações contextuais ao analista para realizar uma avaliação simplificada de explorabilidade.

Ao final da execução, as evidências e a classificação produzidas são exportadas em uma declaração VEX simplificada no formato JSON.

> **Importante:** este projeto é uma prova de conceito acadêmica. A ferramenta não substitui soluções profissionais de SAST, SCA, análise de fluxo de dados ou análise de binários.

---

## Objetivos

A PoC busca demonstrar o seguinte fluxo de análise:

1. Ler o código-fonte de uma aplicação Python;
2. Construir uma Árvore Sintática Abstrata (*Abstract Syntax Tree* — AST);
3. Identificar as funções declaradas no código;
4. Extrair as relações de chamada entre as funções;
5. Construir um grafo de chamadas;
6. Mapear uma CVE para uma função vulnerável;
7. Verificar se a função vulnerável é alcançável a partir de um ponto de entrada;
8. Realizar uma avaliação manual simplificada de explorabilidade;
9. Registrar as evidências utilizadas na decisão;
10. Exportar o resultado em uma declaração VEX simplificada.

---

## Funcionamento

A PoC divide a avaliação em duas etapas principais.

### 1. Análise de alcançabilidade

O protótipo utiliza o módulo `ast` da biblioteca padrão do Python para examinar o código-fonte sem executá-lo.

A partir da AST, são identificadas:

- funções declaradas;
- chamadas diretas entre funções;
- chamadas de métodos;
- relações entre funções chamadoras e funções chamadas.

Essas relações são utilizadas para construir um grafo de chamadas.

Em seguida, o protótipo executa uma busca em profundidade (*Depth-First Search* — DFS) para verificar se existe pelo menos um caminho entre:

- o ponto de entrada informado pelo usuário; e
- a função associada à vulnerabilidade.

Exemplo de caminho encontrado:

```text
main -> process_request -> parse_request -> vulnerable_function
```

Caso não exista um caminho, a vulnerabilidade é classificada como `NOT_AFFECTED`, com a justificativa `code_not_reachable`.

### 2. Avaliação simplificada de explorabilidade

Quando a função vulnerável é alcançável, o programa pode solicitar ao analista as seguintes informações:

1. O atacante controla a entrada que chega à função vulnerável?
2. Existe uma mitigação que impeça a exploração?

As respostas aceitas são:

- `s`: sim;
- `n`: não;
- `d`: desconhecido ou inconclusivo.

---

## Modelo de decisão

A PoC utiliza o seguinte fluxo simplificado de classificação:

```text
Função vulnerável alcançável?
        |
        +-- Não --> NOT_AFFECTED
        |            Justificativa: code_not_reachable
        |
        +-- Sim --> O atacante controla a entrada?
                      |
                      +-- Desconhecido --> UNDER_INVESTIGATION
                      |
                      +-- Não --> NOT_AFFECTED
                      |
                      +-- Sim --> Existe mitigação?
                                    |
                                    +-- Desconhecido
                                    |      --> UNDER_INVESTIGATION
                                    |
                                    +-- Sim
                                    |      --> NOT_AFFECTED
                                    |          Justificativa:
                                    |          protected_by_mitigating_control
                                    |          Risco residual registrado
                                    |
                                    +-- Não
                                           --> AFFECTED
```

A análise de alcançabilidade é automática. A avaliação sobre o controle da entrada e a existência de mitigação depende das informações fornecidas pelo analista.

---

## Estados produzidos

A PoC pode produzir os seguintes estados:

### `AFFECTED`

A vulnerabilidade é classificada como `AFFECTED` quando:

- a função vulnerável é alcançável;
- o atacante controla a entrada que chega à função;
- não existe mitigação identificada.

### `NOT_AFFECTED`

A vulnerabilidade pode ser classificada como `NOT_AFFECTED` quando:

- a função vulnerável não é alcançável;
- a entrada que chega à função não é controlada pelo atacante, dentro do contexto avaliado; ou
- existe uma mitigação considerada efetiva no contexto analisado.

### `UNDER_INVESTIGATION`

A vulnerabilidade é classificada como `UNDER_INVESTIGATION` quando:

- a função é alcançável, mas a análise manual não foi executada;
- não foi possível determinar se o atacante controla a entrada; ou
- não foi possível determinar se existe uma mitigação efetiva.

---

## Estrutura do projeto

```text
VChecker/
├── analyzer.py
├── requirements.txt
├── README.md
├── cases/
│   ├── case1_alcancavel_exploravel.py
│   ├── case2_nao_alcancavel.py
│   └── case3_alcancavel_mitigado.py
├── data/
│   ├── case1.json
│   ├── case2.json
│   └── case3.json
└── results/
```

### Diretórios e arquivos

- `analyzer.py`: programa principal da PoC;
- `cases/`: códigos-fonte utilizados nos casos controlados;
- `data/`: arquivos JSON com o mapeamento entre CVEs e funções vulneráveis;
- `results/`: declarações VEX simplificadas produzidas pelo programa;
- `requirements.txt`: dependências externas do projeto;
- `README.md`: documentação do projeto.

---

## Requisitos

- Python 3.11 ou superior;
- PowerShell, Prompt de Comando ou terminal compatível;
- código-fonte Python disponível para análise.

A versão atual utiliza apenas módulos da biblioteca padrão do Python:

- `argparse`;
- `ast`;
- `json`;
- `datetime`;
- `pathlib`.

Consequentemente, não existem dependências externas obrigatórias para a execução da análise.

---

## Configuração do ambiente

Recomenda-se a utilização de um ambiente virtual Python.

### Windows — PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Windows — Prompt de Comando

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### Linux ou macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Depois de ativar o ambiente virtual, instale as dependências:

```bash
pip install -r requirements.txt
```

Como a versão atual utiliza somente a biblioteca padrão do Python, o arquivo `requirements.txt` contém apenas:

```text
# A PoC utiliza somente módulos da biblioteca padrão do Python.
```

---

## Formato do arquivo de vulnerabilidades

O arquivo informado no argumento `--cves` deve conter uma lista chamada `vulnerabilities`.

Exemplo:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-POC-0001",
      "component": "biblioteca-exemplo",
      "component_version": "1.0.0",
      "function": "vulnerable_function"
    }
  ]
}
```

### Campos

- `id`: identificador da vulnerabilidade;
- `component`: nome do componente associado à vulnerabilidade;
- `component_version`: versão do componente;
- `function`: nome da função associada à vulnerabilidade.

> Os identificadores `CVE-POC-*` utilizados nos casos controlados são fictícios e servem exclusivamente para demonstrar o funcionamento do protótipo.

---

## Execução

### Windows — PowerShell

```powershell
python analyzer.py `
  --source "cases\case1_alcancavel_exploravel.py" `
  --cves "data\case1.json" `
  --entry "main" `
  --product "produto-poc" `
  --version "1.0.0" `
  --output "results\case1-vex.json" `
  --manual
```

Também é possível executar o comando em uma única linha:

```powershell
python analyzer.py --source "cases\case1_alcancavel_exploravel.py" --cves "data\case1.json" --entry "main" --product "produto-poc" --version "1.0.0" --output "results\case1-vex.json" --manual
```

### Linux ou macOS

```bash
python3 analyzer.py \
  --source cases/case1_alcancavel_exploravel.py \
  --cves data/case1.json \
  --entry main \
  --product produto-poc \
  --version 1.0.0 \
  --output results/case1-vex.json \
  --manual
```

---

## Argumentos

### `--source`

Arquivo Python que será submetido à análise estática.

Exemplo:

```text
--source cases/case1_alcancavel_exploravel.py
```

### `--cves`

Arquivo JSON contendo as vulnerabilidades e as funções associadas.

Exemplo:

```text
--cves data/case1.json
```

### `--entry`

Função utilizada como ponto de entrada da análise de alcançabilidade.

O valor padrão é:

```text
main
```

### `--product`

Nome do produto analisado.

Exemplo:

```text
--product produto-poc
```

### `--version`

Versão do produto analisado.

Exemplo:

```text
--version 1.0.0
```

### `--output`

Arquivo JSON no qual a declaração VEX simplificada será gravada.

Exemplo:

```text
--output results/case1-vex.json
```

### `--manual`

Ativa a avaliação manual simplificada de explorabilidade para funções vulneráveis alcançáveis.

Quando esse argumento não é utilizado e a função vulnerável é alcançável, a classificação resultante será `UNDER_INVESTIGATION`.

---

## Casos controlados

### Caso 1 — Função alcançável e explorável

Arquivo:

```text
cases/case1_alcancavel_exploravel.py
```

Caminho esperado:

```text
main -> process_request -> parse_request -> vulnerable_function
```

Respostas esperadas:

```text
O atacante controla a entrada? s
Existe mitigação? n
```

Resultado esperado:

```text
AFFECTED
```

### Caso 2 — Função não alcançável

Arquivo:

```text
cases/case2_nao_alcancavel.py
```

A função vulnerável está presente no código-fonte, mas não existe um caminho entre o ponto de entrada e a função.

Resultado esperado:

```text
NOT_AFFECTED
```

Justificativa esperada:

```text
code_not_reachable
```

Nesse caso, a avaliação manual não é executada.

### Caso 3 — Função alcançável com mitigação

Arquivo:

```text
cases/case3_alcancavel_mitigado.py
```

Respostas esperadas:

```text
O atacante controla a entrada? s
Existe mitigação? s
```

Resultado esperado:

```text
NOT_AFFECTED
```

Justificativa esperada:

```text
protected_by_mitigating_control
```

O risco residual permanece registrado na saída.

---

## Exemplo de saída no terminal

```text
Grafo de chamadas
======================================================================
eval -> []
input -> []
main -> input, process_request
parse_request -> vulnerable_function
process_request -> parse_request
vulnerable_function -> eval

======================================================================
Análise manual: CVE-POC-0001
Função vulnerável: vulnerable_function
Reachability: a função foi classificada como alcançável.
======================================================================
O atacante controla a entrada que chega à função vulnerável? [s/n/d]: s
Existe mitigação que impeça a exploração? [s/n/d]: n
Observações do analista: entrada externa encaminhada para a função.

----------------------------------------------------------------------
CVE: CVE-POC-0001
Função vulnerável: vulnerable_function
Alcançável: True
Caminho: main -> process_request -> parse_request -> vulnerable_function
Estado VEX: AFFECTED
Justificativa: None
```

---

## Exemplo de declaração VEX simplificada

```json
{
  "document": {
    "format": "VEX-SIMPLIFIED-POC",
    "version": "1.0",
    "author": "Reachability Analysis PoC",
    "timestamp": "2026-07-27T22:00:00+00:00"
  },
  "product": {
    "name": "produto-poc",
    "version": "1.0.0",
    "source_file": "cases/case1_alcancavel_exploravel.py",
    "entry_point": "main"
  },
  "vulnerabilities": [
    {
      "id": "CVE-POC-0001",
      "component": "biblioteca-exemplo",
      "component_version": "1.0.0",
      "vulnerable_function": "vulnerable_function",
      "status": "AFFECTED",
      "analysis_state": "exploitable",
      "justification": null,
      "response": [
        "update"
      ],
      "residual_risk": true,
      "evidence": {
        "analysis_type": "static_call_graph",
        "entry_point": "main",
        "vulnerable_function": "vulnerable_function",
        "function_present": true,
        "reachable": true,
        "call_path": [
          "main",
          "process_request",
          "parse_request",
          "vulnerable_function"
        ]
      }
    }
  ]
}
```

---

## VEX simplificado

A saída gerada pelo protótipo é uma representação simplificada e experimental de uma declaração VEX.

O documento registra:

- identificação e versão do produto;
- arquivo analisado;
- ponto de entrada;
- vulnerabilidade analisada;
- função associada à vulnerabilidade;
- resultado da análise de alcançabilidade;
- caminho encontrado no grafo;
- informações fornecidas pelo analista;
- estado atribuído à vulnerabilidade;
- justificativa da classificação;
- resposta recomendada;
- indicação de risco residual.

A saída não implementa integralmente os formatos CSAF, CycloneDX ou OpenVEX.

---

## Limitações

A PoC implementa uma análise estática simplificada e possui as seguintes limitações:

- analisa apenas um arquivo Python por execução;
- não resolve importações entre diferentes módulos;
- não resolve chamadas dinâmicas;
- não analisa reflexão;
- não resolve funções passadas como argumentos;
- não resolve polimorfismo ou métodos sobrescritos;
- não diferencia funções homônimas em módulos ou classes diferentes;
- não analisa *decorators* ou *monkey patching*;
- não interpreta código nativo ou bibliotecas compiladas;
- não executa análise de fluxo de dados;
- não verifica se um caminho é logicamente viável em tempo de execução;
- não determina automaticamente se a entrada é controlada pelo atacante;
- não valida automaticamente a efetividade da mitigação informada.

A existência de um caminho no grafo demonstra alcançabilidade estrutural dentro do modelo analisado, mas não comprova isoladamente a explorabilidade de uma vulnerabilidade.

Da mesma forma, a ausência de um caminho na PoC não representa uma prova formal de que a função seja inalcançável em todos os possíveis cenários de execução.

---

## Aviso de segurança

Os casos controlados podem utilizar construções intencionalmente inseguras, como `eval()`, exclusivamente para fins educacionais e experimentais.

Não utilize os códigos de demonstração em ambientes de produção e não forneça entradas reais ou não confiáveis aos exemplos.

---

## Contexto acadêmico

Este protótipo foi desenvolvido como parte de um trabalho acadêmico relacionado à:

- triagem de vulnerabilidades;
- análise de alcançabilidade;
- avaliação contextual de explorabilidade;
- gestão de vulnerabilidades;
- geração de declarações VEX;
- apoio à documentação de decisões de segurança.

A PoC não pretende substituir ferramentas profissionais de SAST, SCA, DAST, análise de fluxo de dados ou análise de binários.