<p align="center">
  <img src="assets/logo.svg" alt="Vector" width="128" height="128">
</p>

<h1 align="center">Vector — Reachability Analysis PoC</h1>

<p align="center">
  Triagem de vulnerabilidades por alcançabilidade de código, com geração de declarações VEX.
</p>

---

Prova de conceito para triagem de vulnerabilidades baseada em **alcançabilidade de código** (*reachability analysis*), com geração de declarações **VEX** simplificadas.

A ferramenta responde a uma pergunta prática do dia a dia da gestão de vulnerabilidades: *a função vulnerável apontada por uma CVE é realmente alcançável a partir do ponto de entrada da minha aplicação?*

Quando não é, a vulnerabilidade pode ser documentadamente despriorizada. Quando é, a ferramenta conduz o analista por uma avaliação contextual de explorabilidade e registra a decisão com as evidências que a sustentam.

| | |
|---|---|
| **Linguagens analisadas** | Python (`.py`) e C (`.c`, `.h`) |
| **Interfaces** | Gráfica (tkinter) e linha de comando |
| **Escopo da análise** | Um arquivo isolado ou um projeto inteiro |
| **Saída** | VEX em formato próprio e/ou **CycloneDX 1.6** validável, mais grafo de chamadas em PNG/DOT |
| **Requisito mínimo** | Python 3.9 ou superior |

> [!IMPORTANT]
> Este é um protótipo acadêmico. A ferramenta **não substitui** soluções profissionais de SAST, SCA, DAST, análise de fluxo de dados ou análise de binários. Leia [Limitações](#limitações) antes de usar os resultados em qualquer decisão real.

---

## Índice

- [Início rápido](#início-rápido)
- [Visão geral](#visão-geral)
- [Como funciona](#como-funciona)
- [Modelo de decisão](#modelo-de-decisão)
- [Instalação](#instalação)
- [Guia de uso passo a passo](#guia-de-uso-passo-a-passo)
  - [Passo 1 — Preparar o arquivo de CVEs](#passo-1--preparar-o-arquivo-de-cves)
  - [Passo 2 — Definir o escopo da análise](#passo-2--definir-o-escopo-da-análise)
  - [Passo 3 — Executar a análise](#passo-3--executar-a-análise)
  - [Passo 4 — Responder à avaliação de explorabilidade](#passo-4--responder-à-avaliação-de-explorabilidade)
  - [Passo 5 — Interpretar o resultado](#passo-5--interpretar-o-resultado)
- [Referência da linha de comando](#referência-da-linha-de-comando)
- [Formato do arquivo de vulnerabilidades](#formato-do-arquivo-de-vulnerabilidades)
- [Saída produzida](#saída-produzida)
- [Casos controlados](#casos-controlados)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Limitações](#limitações)
- [Solução de problemas](#solução-de-problemas)
- [Aviso de segurança](#aviso-de-segurança)
- [Contexto acadêmico](#contexto-acadêmico)

---

## Início rápido

Para quem quer apenas ver a ferramenta funcionando. Os detalhes de cada etapa estão em [Instalação](#instalação) e no [Guia de uso](#guia-de-uso-passo-a-passo).

**Pré-requisitos:** Python 3.9 ou superior e Git.

**1. Obter o projeto**

```bash
git clone https://github.com/EnricoEng/Vector.git
cd Vector
```

**2. Criar o ambiente e instalar as dependências**

Linux ou macOS:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

**3. Executar um caso pronto**

```bash
python analyzer.py --source cases/case1_alcancavel_exploravel.py --cves data_cves/case1.json --entry main --product teste --version 1.0.0 --output results/teste-vex.json
```

A saída deve terminar com `Declaração VEX salva em: results/teste-vex.json`. Se terminar, está tudo funcionando.

**4. Abrir a interface gráfica**

```bash
python analyzer.py --gui
```

> [!TIP]
> Nenhuma dependência externa é obrigatória para analisar código **Python**. Elas são necessárias para analisar **C** (`tree-sitter`), gerar as **imagens** dos grafos (`graphviz` mais o programa `dot`) e aplicar o **tema escuro** da interface (`ttkbootstrap`). A ferramenta funciona sem cada uma delas, avisando o que deixou de ser feito.

---

## Visão geral

Um scanner de composição de software (SCA) informa que uma dependência possui uma CVE. Isso não significa, por si só, que a aplicação esteja exposta: se a função vulnerável nunca é chamada, o risco prático é substancialmente menor.

Esta PoC automatiza a parte estrutural dessa investigação e organiza a parte contextual.

**O que a ferramenta faz:**

1. lê o código-fonte sem executá-lo;
2. constrói um grafo de chamadas entre funções;
3. verifica se existe caminho entre o ponto de entrada e a função vulnerável;
4. quando existe, conduz o analista por duas perguntas contextuais;
5. classifica a vulnerabilidade e exporta a decisão com suas evidências.

**O que a ferramenta não faz:**

- não executa o código nem realiza testes dinâmicos;
- não determina automaticamente se o atacante controla a entrada;
- não valida a efetividade da mitigação informada;
- não comprova explorabilidade — comprova apenas alcançabilidade estrutural.

---

## Como funciona

A avaliação é dividida em duas etapas: uma automática e uma assistida.

### Etapa 1 — Análise de alcançabilidade (automática)

O protótipo examina o código-fonte sem executá-lo, utilizando um analisador sintático diferente para cada linguagem:

| Linguagem | Analisador | Origem |
|---|---|---|
| Python | módulo `ast` | biblioteca padrão |
| C | `tree-sitter` + `tree-sitter-c` | dependência externa |

O `tree-sitter` foi escolhido para a linguagem C por dois motivos. Primeiro, não exige que o arquivo seja pré-processado — diretivas como `#include` e `#define` não precisam ser resolvidas antes da análise. Segundo, é tolerante a erros, produzindo uma árvore parcial mesmo quando parte do arquivo não pode ser reconhecida, situação comum ao analisar código isoladamente, sem os cabeçalhos do sistema.

A partir da árvore sintática, são identificadas as funções declaradas, as chamadas diretas entre funções, as chamadas de métodos e as relações entre chamadoras e chamadas. Essas relações formam o grafo de chamadas.

Em seguida, uma busca em profundidade (*Depth-First Search* — DFS) verifica se existe pelo menos um caminho entre o ponto de entrada informado e a função associada à vulnerabilidade:

```text
main -> process_request -> parse_request -> vulnerable_function
```

Quando nenhum caminho existe, a vulnerabilidade é classificada como `NOT_AFFECTED`, com a justificativa `code_not_reachable`, e a etapa 2 não é executada.

### Etapa 2 — Avaliação de explorabilidade (assistida)

Alcançabilidade não é explorabilidade. Uma função pode ser alcançável e ainda assim não representar risco, seja porque o atacante não controla a entrada que chega até ela, seja porque existe uma mitigação no caminho.

Essas duas informações dependem do contexto operacional e não podem ser extraídas do grafo. Por isso, quando a função é alcançável, a ferramenta pergunta ao analista:

1. **O atacante controla a entrada que chega à função vulnerável?**
2. **Existe uma mitigação que impeça a exploração?**

A segunda pergunta só é considerada quando a resposta à primeira é afirmativa. Ambas aceitam três respostas: sim, não e **desconhecido**.

A resposta "desconhecido" é deliberada: ela leva a vulnerabilidade ao estado `UNDER_INVESTIGATION`, registrando honestamente a incerteza em vez de forçar uma conclusão sem fundamento.

---

## Modelo de decisão

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
                      |            Justificativa:
                      |            attacker_controlled_input_not_present
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

### Estados produzidos

| Estado | `analysis_state` | Quando é atribuído |
|---|---|---|
| `AFFECTED` | `exploitable` | Função alcançável, entrada controlada pelo atacante e sem mitigação identificada |
| `NOT_AFFECTED` | `not_affected` | Função não alcançável; **ou** entrada não controlada pelo atacante; **ou** mitigação efetiva no contexto avaliado |
| `UNDER_INVESTIGATION` | `in_triage` | Função alcançável, mas a avaliação manual não foi feita ou foi inconclusiva |

O campo `residual_risk` permanece `true` quando a classificação `NOT_AFFECTED` decorre de uma mitigação, e não da ausência de caminho. A distinção importa: uma mitigação pode ser removida em uma alteração futura do código.

---

## Instalação

### Passo 1 — Verificar a versão do Python

```bash
python --version
```

É necessário Python **3.9 ou superior**. No macOS e no Linux, use `python3` no lugar de `python` em todos os comandos deste guia.

Para usar a interface gráfica, verifique também a versão do Tk:

```bash
python -c "import tkinter; print(tkinter.TkVersion)"
```

O resultado precisa ser **8.6 ou superior**. As versões 8.6 e 9.0 foram testadas. Se o resultado for `8.5`, consulte o aviso ao final desta seção.

### Passo 2 — Obter o projeto

```bash
git clone https://github.com/EnricoEng/Vector.git
cd Vector
```

Sem o Git instalado, use o botão **Code → Download ZIP** na página do repositório e extraia o arquivo.

Todos os comandos deste guia pressupõem que o terminal está aberto na pasta do projeto.

### Passo 3 — Criar e ativar um ambiente virtual

**Windows — PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows — Prompt de Comando**

```cmd
python -m venv .venv
.venv\Scripts\activate
```

**Linux ou macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Passo 4 — Instalar as dependências

Com o ambiente virtual ativado:

```bash
pip install -r requirements.txt
```

| Pacote | Finalidade | O que acontece sem ele |
|---|---|---|
| `tree-sitter`, `tree-sitter-c` | Análise de código C | A análise de C é interrompida com uma mensagem orientando a instalação. A análise de Python não é afetada |
| `graphviz` | Grafo de chamadas | A análise conclui normalmente e apenas a imagem PNG deixa de ser gerada |
| `ttkbootstrap` | Tema escuro da interface | A janela usa o tema `clam` do próprio `ttk`, com todas as funcionalidades idênticas |

Nenhuma delas é obrigatória para analisar código Python.

#### Tema da interface

Quando o `ttkbootstrap` está instalado **e** o Tk é 8.6 ou superior, a janela usa o tema escuro `superhero`, escolhido por acompanhar o azul-marinho da logo. Caso contrário, é usado o tema `clam` do `ttk`.

As duas condições são verificadas em conjunto porque o `ttkbootstrap` desenha seus widgets a partir de imagens PNG: no Tk 8.5 a criação da janela falharia com `couldn't recognize image data`.

A interface é tolerante a falhas nessa etapa. Se a aplicação do tema não funcionar — por exemplo em uma combinação de versões não prevista —, a janela avisa no terminal, volta ao tema padrão e abre normalmente. Nunca se fica sem interface por causa do tema.

As cores do registro de execução acompanham o tema: fundo escuro com texto claro em temas escuros, fundo branco com texto escuro em temas claros. A decisão é tomada pela luminância da cor de fundo, de modo que qualquer tema escolhido seja tratado corretamente.

Para trocar o tema, altere a constante `BOOTSTRAP_THEME` em [vector/gui.py](vector/gui.py). Os temas escuros disponíveis são `superhero`, `darkly`, `cyborg`, `solar` e `vapor`; entre os claros estão `cosmo`, `flatly` e `yeti`.

> [!NOTE]
> As versões de `tree-sitter` e `tree-sitter-c` estão fixadas no `requirements.txt`. O `tree-sitter` valida a versão da ABI da gramática, e combinações mais recentes de `tree-sitter-c` são recusadas por versões mais antigas de `tree-sitter`, com o erro `Incompatible Language version`.

### Passo 5 — Instalar o Graphviz (opcional)

O pacote Python `graphviz` apenas escreve o arquivo DOT e invoca o programa externo `dot`, que é instalado separadamente a partir de [graphviz.org/download](https://graphviz.org/download/).

Sem ele, a ferramenta continua funcionando: a análise é concluída, o arquivo DOT é gravado e apenas a imagem PNG deixa de ser gerada. A ausência da figura é registrada como aviso e não altera a conclusão sobre alcançabilidade.

Para verificar se o programa está acessível:

```bash
dot -V
```

### Passo 6 — Verificar a instalação

Analisando um caso em **Python**, que não exige dependências externas:

```bash
python analyzer.py --source cases/case1_alcancavel_exploravel.py --cves data_cves/case1.json --entry main --product teste --version 1.0.0 --output results/teste-vex.json
```

A saída deve terminar com `Declaração VEX salva em: results/teste-vex.json`.

Analisando um caso em **C**, que confirma a instalação do `tree-sitter`:

```bash
python analyzer.py --source cases/case4_c_alcancavel_exploravel.c --cves data_cves/case1.json --entry main --product teste --version 1.0.0 --output results/teste-c-vex.json
```

Nos dois casos, o caminho encontrado deve ser:

```text
main -> process_request -> parse_request -> vulnerable_function
```

E a interface gráfica:

```bash
python analyzer.py --gui
```

### Requisito adicional para a interface gráfica

A interface usa `tkinter`, que acompanha as instalações oficiais do Python no Windows e no macOS. Em algumas distribuições Linux ele é distribuído separadamente:

```bash
sudo apt install python3-tk
```

> [!WARNING]
> **É necessário Tk 8.6 ou superior.** O Python das *Command Line Tools* do macOS, em `/usr/bin/python3`, usa o Tcl/Tk **8.5.9**, versão depreciada pela Apple desde o macOS 10.14. Nas versões recentes do sistema, ela abre a janela mas **não desenha os campos**, resultando em uma tela inteiramente branca. A ferramenta detecta essa situação e avisa no terminal. Consulte [Solução de problemas](#a-interface-gráfica-abre-em-branco-no-macos).

---

## Guia de uso passo a passo

### Passo 1 — Preparar o arquivo de CVEs

A ferramenta precisa saber **qual função** está associada a cada vulnerabilidade. Essa informação vem de um arquivo JSON que você monta a partir do relatório do seu scanner SCA e do *advisory* da CVE.

Crie um arquivo, por exemplo `data_cves/minhas-cves.json`:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "component": "biblioteca-exemplo",
      "component_version": "1.0.0",
      "function": "parse_untrusted_input"
    }
  ]
}
```

O campo mais importante é `function`: ele deve conter o **nome exato** da função vulnerável, como ela aparece no código-fonte. Consulte o [formato completo](#formato-do-arquivo-de-vulnerabilidades) para a descrição de cada campo.

### Passo 2 — Definir o escopo da análise

Decida o que será analisado:

| Escopo | Quando usar | Exemplo |
|---|---|---|
| Um arquivo | Verificação pontual, casos controlados | `cases/case1_alcancavel_exploravel.py` |
| Uma pasta | Aplicação real com vários módulos | `src/` |

Ao analisar uma pasta, todos os arquivos da linguagem escolhida são lidos recursivamente e seus grafos são unidos em um único grafo de chamadas. As pastas `.venv`, `venv`, `env`, `__pycache__`, `.git`, `node_modules`, `build` e `dist` são ignoradas, por conterem código de terceiros ou artefatos de compilação que distorceriam o resultado.

> [!IMPORTANT]
> O escopo precisa incluir o arquivo que **declara** a função vulnerável. Se ele ficar de fora, a função não aparecerá no grafo e o resultado será `NOT_AFFECTED` por um motivo errado. A ferramenta emite um aviso explícito quando a função não é encontrada — leia os avisos antes de aceitar a conclusão.

### Passo 3 — Executar a análise

Escolha uma das duas interfaces.

#### Opção A — Interface gráfica (recomendada para uso interativo)

```bash
python analyzer.py --gui
```

Na janela, preencha os campos na ordem:

1. **Linguagem do código-fonte** — selecione `Python (.py)`, `C (.c / .h)` ou deixe em `Detectar automaticamente`.
   A escolha manual tem prioridade sobre a extensão do arquivo e também define o filtro do seletor de arquivos. Use-a quando o código tiver uma extensão incomum.

2. **Código-fonte** — clique em `Arquivo...` para analisar um arquivo isolado, ou em `Pasta...` para analisar um projeto inteiro.

3. **Arquivo de CVEs (JSON)** — clique em `Abrir...` e selecione o arquivo preparado no Passo 1.

4. **Ponto de entrada** — clique em `Detectar`.
   A ferramenta analisa o código e preenche a lista com as funções encontradas, colocando primeiro as que não são chamadas por nenhuma outra, que são as raízes do grafo e as candidatas naturais a ponto de entrada. Você também pode digitar o nome diretamente.

5. **Nome e versão do produto** — identificação que constará na declaração VEX.

6. **Declaração VEX (saída)** — clique em `Salvar...` e escolha onde gravar o resultado.

7. **Formato da declaração** — escolha entre `Formato próprio da PoC`, `CycloneDX 1.6 VEX` ou `Os dois formatos`.
   Com a última opção, o documento CycloneDX é gravado ao lado do outro, com o sufixo `.cdx` antes da extensão.

8. Mantenha marcada a opção **Perguntar sobre explorabilidade quando a função for alcançável** para realizar a avaliação do Passo 4.

9. Clique em **Analisar**.

O andamento e o resultado aparecem no registro da própria janela. Os grafos são gravados em uma subpasta `graphs/` ao lado do arquivo de saída, e o botão `Abrir pasta dos resultados` leva até eles.

#### Opção B — Linha de comando (recomendada para automação)

**Linux ou macOS**

```bash
python3 analyzer.py \
  --source cases/case1_alcancavel_exploravel.py \
  --cves data_cves/case1.json \
  --entry main \
  --product produto-poc \
  --version 1.0.0 \
  --output results/case1-vex.json \
  --manual
```

**Windows — PowerShell**

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

Analisando um projeto em C, com detecção automática da linguagem:

```bash
python3 analyzer.py \
  --source src/ \
  --cves data_cves/minhas-cves.json \
  --entry main \
  --product minha-aplicacao \
  --version 2.1.0 \
  --output results/minha-aplicacao-vex.json \
  --manual
```

> [!TIP]
> Omita `--manual` para executar a análise sem interação. Toda função alcançável será classificada como `UNDER_INVESTIGATION`, o que é adequado para uma triagem automatizada inicial em pipelines de CI.

### Passo 4 — Responder à avaliação de explorabilidade

Quando a função vulnerável é alcançável e a avaliação manual está ativa, a ferramenta apresenta o caminho encontrado e faz as duas perguntas.

No terminal, as respostas aceitas são `s` (sim), `n` (não) e `d` (desconhecido). Na interface gráfica, as mesmas opções aparecem como botões, e `Não sei responder` equivale a "desconhecido".

```text
======================================================================
Análise manual: CVE-POC-0001
Função vulnerável: vulnerable_function
Reachability: a função foi classificada como alcançável.
Caminho: main -> process_request -> parse_request -> vulnerable_function
======================================================================
O atacante controla a entrada que chega à função vulnerável? [s/n/d]: s
Existe mitigação que impeça a exploração? [s/n/d]: n
Observações do analista: Entrada externa encaminhada para a função.
```

Ao responder, considere o **caminho exibido**: ele mostra por onde os dados trafegam até a função vulnerável. Se nenhuma das funções do caminho recebe dados de fora do sistema, a resposta à primeira pergunta provavelmente é "não".

Se você não tiver certeza, responda `d`. O estado `UNDER_INVESTIGATION` é um resultado legítimo e preferível a uma conclusão sem base.

### Passo 5 — Interpretar o resultado

A saída no terminal traz o grafo de chamadas e a conclusão por vulnerabilidade:

```text
Grafo de chamadas
======================================================================
fgets -> []
helper -> printf
main -> helper, fgets, process_request
parse_request -> vulnerable_function
printf -> []
process_request -> parse_request
system -> []
vulnerable_function -> system

----------------------------------------------------------------------
CVE: CVE-POC-0001
Função vulnerável: vulnerable_function
Alcançável: True
Caminho: main -> process_request -> parse_request -> vulnerable_function
Estado VEX: AFFECTED
Justificativa: None
Conclusão: A função vulnerável é alcançável, recebe entrada controlada
pelo atacante e não possui mitigação identificada.

======================================================================
Declaração VEX salva em: results/case1-vex.json
```

**Antes de aceitar a conclusão, verifique os avisos.** Eles aparecem no terminal com o prefixo `Aviso:` e ficam registrados no campo `analysis_scope.warnings` da declaração VEX. Os principais são:

| Aviso | Significado |
|---|---|
| Função não encontrada no código analisado | O escopo pode não incluir o arquivo que declara a função. O resultado `NOT_AFFECTED` é pouco confiável |
| Funções declaradas em mais de um arquivo | Há homônimos tratados como uma única função. O caminho encontrado pode não existir no programa real |
| Arquivo analisado parcialmente | Trechos não reconhecidos, geralmente por dependerem de macros ou cabeçalhos ausentes. A cobertura é incompleta |
| Programa `dot` não encontrado | Apenas a imagem PNG não foi gerada. Não afeta a conclusão |

---

## Referência da linha de comando

| Argumento | Obrigatório | Padrão | Descrição |
|---|---|---|---|
| `--gui` | — | — | Abre a interface gráfica. Torna os demais argumentos dispensáveis |
| `--source` | Sim | — | Arquivo ou pasta a ser analisado |
| `--cves` | Sim | — | Arquivo JSON que mapeia CVE para função |
| `--product` | Sim | — | Nome do produto analisado |
| `--version` | Sim | — | Versão do produto analisado |
| `--output` | Sim | — | Arquivo JSON que receberá a declaração VEX |
| `--entry` | Não | `main` | Função usada como ponto de entrada |
| `--language` | Não | detectar | Linguagem do código: `python` ou `c` |
| `--format` | Não | `poc` | Formato da declaração: `poc`, `cyclonedx` ou `ambos` |
| `--graphs` | Não | `results/graphs` | Pasta que receberá os grafos gerados |
| `--manual` | Não | desativado | Ativa a avaliação de explorabilidade para funções alcançáveis |

### Escolha do formato de saída

| Valor | Arquivo gerado | Quando usar |
|---|---|---|
| `poc` | O caminho informado em `--output` | Formato próprio, com todas as evidências de alcançabilidade. Padrão |
| `cyclonedx` | O caminho informado em `--output` | Interoperabilidade com ferramentas que consomem CycloneDX |
| `ambos` | `--output` e o mesmo caminho com sufixo `.cdx` | Quando você precisa das evidências completas e de um documento padronizado |

Com `--format ambos` e `--output results/vex.json`, são gerados `results/vex.json` e `results/vex.cdx.json`. O sufixo evita que um formato sobrescreva o outro.

Consulte [Interoperabilidade](#interoperabilidade-e-limites-do-cyclonedx) para o que o documento CycloneDX contém e o que ele não resolve.

### Detecção automática de linguagem

Quando `--language` é omitido, a linguagem é determinada pela extensão dos arquivos. Para uma pasta, é escolhida a linguagem com maior número de arquivos — critério que evita que um único script auxiliar em Python faça um projeto em C ser analisado como Python.

Informe `--language` explicitamente quando a detecção não corresponder à sua intenção.

---

## Formato do arquivo de vulnerabilidades

O arquivo informado em `--cves` deve conter uma lista chamada `vulnerabilities`:

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

| Campo | Obrigatório | Descrição |
|---|---|---|
| `id` | Sim | Identificador da vulnerabilidade |
| `function` | Sim | Nome exato da função associada à vulnerabilidade |
| `component` | Não | Nome do componente afetado |
| `component_version` | Não | Versão do componente |

O arquivo é validado antes do início da análise. Erros de formato produzem uma mensagem indicando a posição exata do problema, em vez de falharem no meio da execução.

> Os identificadores `CVE-POC-*` usados nos casos controlados são fictícios e servem exclusivamente para demonstrar o funcionamento do protótipo.

---

## Saída produzida

A ferramenta gera dois formatos, selecionáveis por `--format` ou pela interface gráfica.

| | Formato próprio (`poc`) | CycloneDX (`cyclonedx`) |
|---|---|---|
| Padronizado | Não | Sim — CycloneDX 1.6 |
| Validável por schema | Não | Sim |
| Consumível por outras ferramentas | Não | Sim |
| Evidências de alcançabilidade | Campos dedicados | Propriedades `vector:*` |
| Escopo e avisos da análise | Bloco `analysis_scope` | Não representável |

O formato próprio continua sendo o padrão porque registra a análise de alcançabilidade em campos dedicados — informação que a especificação do CycloneDX não prevê e que é o objeto central deste trabalho.

### Declaração VEX simplificada

```json
{
  "document": {
    "format": "VEX-SIMPLIFIED-POC",
    "version": "1.1",
    "author": "Reachability Analysis PoC",
    "timestamp": "2026-07-27T22:00:00+00:00"
  },
  "product": {
    "name": "produto-poc",
    "version": "1.0.0",
    "source_file": "cases/case1_alcancavel_exploravel.py",
    "entry_point": "main"
  },
  "analysis_scope": {
    "language": "python",
    "analyzed_files": [
      "cases/case1_alcancavel_exploravel.py"
    ],
    "analyzed_file_count": 1,
    "warnings": []
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
      "detail": "A função vulnerável é alcançável, recebe entrada controlada pelo atacante e não possui mitigação identificada.",
      "evidence": {
        "analysis_type": "static_call_graph",
        "language": "python",
        "entry_point": "main",
        "vulnerable_function": "vulnerable_function",
        "function_present": true,
        "declared_in": [
          "cases/case1_alcancavel_exploravel.py"
        ],
        "reachable": true,
        "call_path": [
          "main",
          "process_request",
          "parse_request",
          "vulnerable_function"
        ],
        "manual_assessment": {
          "attacker_input": true,
          "mitigation_present": false,
          "mitigation_description": null,
          "analyst_notes": "Entrada obtida via input()."
        },
        "call_graph_dot": "results/graphs/CVE-POC-0001_call_graph.dot",
        "call_graph_image": "results/graphs/CVE-POC-0001_call_graph.png"
      }
    }
  ]
}
```

O documento registra a identificação do produto, o escopo real da análise, o resultado da alcançabilidade, o caminho encontrado, as informações fornecidas pelo analista, o estado atribuído, a justificativa, a resposta recomendada e a indicação de risco residual.

O bloco `analysis_scope` foi introduzido na versão 1.1 do formato. Ele registra a linguagem, os arquivos efetivamente lidos e os avisos produzidos, permitindo avaliar se a cobertura da análise sustenta a conclusão — informação que se tornou essencial quando a ferramenta passou a aceitar projetos inteiros.

> Este formato é uma representação simplificada e experimental. Ele **não é** CSAF, CycloneDX ou OpenVEX, e não é aceito por ferramentas de terceiros. Para interoperar, use `--format cyclonedx`.

### Declaração CycloneDX 1.6

Com `--format cyclonedx`, a ferramenta gera um documento que **passa na validação do schema oficial** do CycloneDX 1.6:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:5efcc2cb-fd31-4f99-a5c8-3e84089bf637",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-27T22:00:00+00:00",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "Vector — Reachability Analysis PoC",
          "version": "2.1.0"
        }
      ]
    },
    "component": {
      "bom-ref": "product-produto-poc@1.0.0",
      "type": "application",
      "name": "produto-poc",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "component-biblioteca-exemplo@1.0.0",
      "type": "library",
      "name": "biblioteca-exemplo",
      "version": "1.0.0"
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln-CVE-POC-0001",
      "id": "CVE-POC-0001",
      "analysis": {
        "state": "exploitable",
        "detail": "A função vulnerável é alcançável... Caminho de chamadas: main -> process_request -> parse_request -> vulnerable_function.",
        "response": ["update"]
      },
      "affects": [
        { "ref": "component-biblioteca-exemplo@1.0.0" }
      ],
      "properties": [
        { "name": "vector:reachable", "value": "true" },
        { "name": "vector:entry_point", "value": "main" },
        { "name": "vector:call_path", "value": "main -> process_request -> parse_request -> vulnerable_function" }
      ]
    }
  ]
}
```

Como a especificação não possui campos para caminho de chamadas, ponto de entrada ou arquivos de declaração, essas evidências são registradas na lista `properties`, com o prefixo `vector:` para deixar claro que não fazem parte do padrão.

#### Correspondência entre as justificativas

O campo `justification` do CycloneDX é um enumerado fechado com nove valores. Duas das justificativas da PoC já pertencem a esse conjunto; a terceira precisa ser aproximada:

| Justificativa da PoC | Valor no CycloneDX | Observação |
|---|---|---|
| `code_not_reachable` | `code_not_reachable` | Correspondência exata |
| `protected_by_mitigating_control` | `protected_by_mitigating_control` | Correspondência exata |
| `attacker_controlled_input_not_present` | `requires_environment` | **Aproximação** |

O valor `attacker_controlled_input_not_present` não existe na especificação. A aproximação escolhida foi `requires_environment`, cuja definição oficial é *"Exploitability requires a certain environment which is not present"*: a exploração exigiria um contexto em que dados controlados pelo atacante alcancem a função, e esse contexto não está presente no ambiente avaliado.

Sempre que uma aproximação ocorre, a justificativa original é preservada na propriedade `vector:original_justification`, de modo que nenhuma informação se perde.

#### Interoperabilidade e limites do CycloneDX

O documento pode ser consumido por ferramentas que implementam a especificação. O destino mais direto é o **Dependency-Track**, que ingere VEX no formato CycloneDX, e o `cyclonedx-cli`, que valida o arquivo:

```bash
cyclonedx-cli validate --input-file results/vex.cdx.json
```

> [!NOTE]
> **Sobre o Black Duck.** A documentação do Black Duck SCA descreve a *geração* de relatórios VEX, no formato CSAF 2.0 (profile 5), mas não descreve importação de documentos VEX externos. O caminho documentado para registrar uma decisão de remediação vinda de fora é a REST API (`PUT .../vulnerabilities/{vulnerabilityId}/remediation`), e não o upload de arquivo. Confirme na documentação da sua licença antes de planejar uma integração.

O que o CycloneDX **não** carrega: o bloco `analysis_scope`, com a linguagem analisada, a lista de arquivos lidos e os avisos de cobertura. Essa informação existe apenas no formato próprio. Ao usar `--format ambos`, os dois arquivos são complementares — o CycloneDX para interoperar, o formato próprio para auditar a análise.

### Grafo de chamadas

Para cada vulnerabilidade são gerados um arquivo `.dot` editável e uma imagem `.png`, nomeados a partir do identificador da CVE.

| Cor | Significado |
|---|---|
| Azul | Ponto de entrada |
| Vermelho | Função vulnerável alcançável |
| Laranja | Função vulnerável não alcançável |
| Verde | Funções e arestas do caminho encontrado |
| Cinza | Demais funções |

---

## Casos controlados

O diretório `cases/` contém casos que demonstram cada resultado possível. Os casos em C reutilizam `data_cves/case1.json`, pois a função vulnerável tem o mesmo nome nas duas linguagens.

| # | Arquivo | Linguagem | Respostas | Resultado esperado |
|---|---|---|---|---|
| 1 | `case1_alcancavel_exploravel.py` | Python | entrada: `s`, mitigação: `n` | `AFFECTED` |
| 2 | `case2_nao_alcancavel.py` | Python | não perguntadas | `NOT_AFFECTED` / `code_not_reachable` |
| 3 | `case3_alcancavel_mitigado.py` | Python | entrada: `s`, mitigação: `s` | `NOT_AFFECTED` / `protected_by_mitigating_control` |
| 4 | `case4_c_alcancavel_exploravel.c` | C | entrada: `s`, mitigação: `n` | `AFFECTED` |
| 5 | `case5_c_nao_alcancavel.c` | C | não perguntadas | `NOT_AFFECTED` / `code_not_reachable` |

Os casos 1 e 4 reproduzem a mesma cadeia de chamadas em linguagens diferentes, o que permite comparar diretamente o comportamento dos dois analisadores sintáticos:

```text
main -> process_request -> parse_request -> vulnerable_function
```

Nos casos 2 e 5, a função vulnerável está presente no código, mas nenhuma cadeia de chamadas parte do ponto de entrada e chega até ela. A avaliação manual não é executada.

No caso 3, o risco residual permanece registrado na saída, pois a classificação decorre de uma mitigação e não da ausência de caminho.

Para executar o caso 4:

```bash
python3 analyzer.py \
  --source cases/case4_c_alcancavel_exploravel.c \
  --cves data_cves/case1.json \
  --entry main \
  --product produto-poc \
  --version 1.0.0 \
  --output results/case4-vex.json \
  --manual
```

---

## Estrutura do projeto

```text
Vector/
├── analyzer.py                 Ponto de entrada em linha de comando
├── requirements.txt
├── README.md
├── vector/                     Pacote com a lógica da PoC
│   ├── analysis.py             Fluxo completo, usado pelas duas interfaces
│   ├── cyclonedx.py            Exportação em CycloneDX 1.6
│   ├── errors.py               Exceções previstas
│   ├── graph_image.py          Representação visual do grafo
│   ├── gui.py                  Interface gráfica (tkinter)
│   ├── logo.py                 Logo: carga do PNG e desenho no Canvas
│   ├── reachability.py         Busca em profundidade sobre o grafo
│   ├── version.py              Versão da PoC
│   ├── vex.py                  Classificação e declaração VEX própria
│   └── parsers/
│       ├── __init__.py         Seleção do analisador por linguagem
│       ├── base.py             Estrutura comum e busca de arquivos
│       ├── c_parser.py         Analisador de C (tree-sitter)
│       └── python_parser.py    Analisador de Python (ast)
├── assets/                     Logo em SVG e PNG
├── tools/
│   └── render_logo.py          Regera os PNGs da logo a partir de logo.py
├── cases/                      Códigos-fonte dos casos controlados
├── data_cves/                  Mapeamentos entre CVEs e funções
└── results/                    Declarações VEX produzidas
    └── graphs/                 Grafos em PNG e DOT
```

### Sobre a logo

A logo é usada em três lugares, todos derivados da mesma geometria, declarada em [vector/logo.py](vector/logo.py):

| Onde | Arquivo | Motivo |
|---|---|---|
| README | `assets/logo.svg` | O GitHub renderiza SVG, que fica nítido em qualquer zoom |
| Interface gráfica | `assets/logo-64.png` | O Canvas do Tk não aplica antialiasing no Windows; a imagem tem suavização verdadeira |
| Alternativa | Desenho no Canvas | Usada quando o PNG não pode ser carregado, como no Tk 8.5 do macOS |

Os PNGs são versionados no repositório. O script `tools/render_logo.py` só é executado quando a logo muda, e por isso o **Pillow não é dependência de execução** da ferramenta:

```bash
pip install pillow
python tools/render_logo.py
```

A separação entre `analysis.py` e as duas interfaces garante que a linha de comando e a interface gráfica produzam exatamente o mesmo resultado, pois ambas chamam a mesma função.

Os arquivos `analyzer_1th_version.py` e `analyzer_2th_version.py` preservam versões anteriores do protótipo e documentam a evolução do trabalho.

---

## Limitações

A PoC implementa uma análise estática simplificada e possui limitações que precisam ser consideradas na leitura dos resultados.

### Gerais

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

### Específicas da análise de C

- não executa o pré-processador: funções geradas por macros não são identificadas, e trechos que dependem de macros ausentes podem não ser reconhecidos;
- não segue `#include`: apenas os arquivos indicados no escopo são lidos;
- registra chamadas por ponteiro de função pelo nome da variável que armazena o ponteiro, sem resolver qual função ela aponta em tempo de execução;
- não avalia compilação condicional: trechos sob `#if` são tratados como se estivessem ativos;
- considera apenas definições de função; protótipos não geram nós no grafo, por não possuírem corpo.

### Projetos com vários arquivos

Ao analisar uma pasta, os grafos de todos os arquivos são unidos e as funções são identificadas apenas pelo nome. Duas funções homônimas declaradas em arquivos diferentes são tratadas como uma só, o que pode criar um caminho de alcançabilidade inexistente no programa real.

Quando isso é detectado, a ferramenta registra um aviso em `analysis_scope.warnings`, informando quais funções foram afetadas. O mesmo campo registra os arquivos que não puderam ser analisados ou que foram reconhecidos apenas em parte.

### Interpretação dos resultados

A existência de um caminho no grafo demonstra **alcançabilidade estrutural** dentro do modelo analisado, mas não comprova isoladamente a explorabilidade de uma vulnerabilidade.

Da mesma forma, a ausência de um caminho **não representa prova formal** de que a função seja inalcançável em todos os cenários de execução possíveis.

---

## Solução de problemas

### A interface gráfica abre em branco no macOS

O Python distribuído com as *Command Line Tools*, em `/usr/bin/python3`, usa o Tcl/Tk **8.5.9** — versão congelada por volta de 2010 e depreciada pela Apple desde o macOS 10.14. Nas versões recentes do sistema, ela abre a janela mas não desenha os widgets.

Verifique a versão instalada:

```bash
python3 -c "import tkinter; print(tkinter.TkVersion)"
```

Se o resultado for `8.5`, instale o Python a partir de [python.org/downloads/macos](https://www.python.org/downloads/macos/) e execute a PoC com esse interpretador. Os instaladores atuais acompanham o Tk 8.6 ou 9.0, e ambos funcionam. A ferramenta avisa no terminal quando detecta uma versão insuficiente.

A análise pela linha de comando não é afetada e funciona normalmente com qualquer uma das versões.

### A janela abre, mas sem o tema escuro

O `ttkbootstrap` não está instalado no interpretador em uso, ou o tema não pôde ser aplicado. A interface funciona normalmente com o tema padrão; para obter o tema escuro:

```bash
pip install ttkbootstrap
```

Confirme que está usando o mesmo interpretador em que instalou o pacote — é comum instalar em um Python e executar com outro. Se a aplicação do tema falhar, o motivo aparece no terminal ao abrir a janela.

### `Incompatible Language version`

As versões instaladas de `tree-sitter` e `tree-sitter-c` são incompatíveis entre si. Reinstale as versões fixadas:

```bash
pip install -r requirements.txt
```

### `A análise de código C exige os pacotes tree-sitter e tree-sitter-c`

As dependências de C não estão instaladas. Execute `pip install -r requirements.txt`. A análise de código Python não é afetada e continua funcionando sem elas.

### `O ponto de entrada '...' não foi encontrado no código analisado`

O nome informado em `--entry` não existe no grafo. A mensagem lista os pontos de entrada prováveis encontrados no código. Na interface gráfica, o botão `Detectar` preenche a lista automaticamente.

### `O programa 'dot', do Graphviz, não foi encontrado no sistema`

Apenas a imagem PNG deixa de ser gerada; o arquivo DOT é gravado e a análise conclui normalmente. Para obter as imagens, instale o Graphviz a partir de [graphviz.org/download](https://graphviz.org/download/).

### A função vulnerável não foi encontrada no código analisado

O escopo da análise provavelmente não inclui o arquivo que declara a função. Verifique o valor de `--source` e considere apontá-lo para a pasta raiz do projeto. Um resultado `NOT_AFFECTED` acompanhado desse aviso não é confiável.

---

## Aviso de segurança

Os casos controlados utilizam construções intencionalmente inseguras — como `eval()` em Python e `system()` em C — exclusivamente para fins educacionais e experimentais.

**Não utilize os códigos de demonstração em ambientes de produção e não forneça entradas reais ou não confiáveis aos exemplos.**

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
