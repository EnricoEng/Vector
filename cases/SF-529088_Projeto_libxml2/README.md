# SF-529088 — Qt WebEngine e a CVE-2022-49043 no libxml2

Caso construído a partir do **código-fonte real** do Qt WebEngine 5.15.12 LTS, e não de uma reprodução.

A versão do libxml2 embutida é a **2.9.12**, que está dentro da faixa afetada pela CVE. Um SCA baseado apenas em número de versão classificaria o produto como vulnerável.

A conclusão obtida é outra, e mais forte do que a esperada no início da investigação: a função vulnerável não é apenas inalcançável — ela **não existe no binário**, porque o Chromium a exclui da compilação.

Este é exatamente o cenário em que a análise de alcançabilidade se justifica: a versão é vulnerável, e o que protege o produto é como ele foi construído.

## A vulnerabilidade

| | |
|---|---|
| **CVE** | [CVE-2022-49043](https://nvd.nist.gov/vuln/detail/CVE-2022-49043) |
| **Componente** | libxml2 |
| **Versões afetadas** | anteriores a 2.11.0 |
| **Versão embutida no Qt WebEngine 5.15.12** | **2.9.12** — dentro da faixa afetada |
| **Função vulnerável** | `xmlXIncludeAddNode`, em `xinclude.c` |
| **Tipo** | Use-after-free (CWE-416) |
| **CVSS** | 7.8 (NVD) / 8.1 (MITRE) |

> [!IMPORTANT]
> Não confundir com a **CVE-2023-46233**, que trata dos padrões fracos de PBKDF2 no `crypto-js` e não tem relação com o libxml2.

## Origem do código

O Chromium usado pelo Qt WebEngine é um submódulo git (`src/3rdparty`, apontando para `qtwebengine-chromium.git`). O código deste caso foi obtido assim:

O commit do Chromium não é uma branch, e sim um **ponteiro fixo** gravado no repositório do Qt WebEngine. Ele é recuperado assim:

```bash
git clone --depth 1 --branch v5.15.12-lts https://code.qt.io/qt/qtwebengine.git
cd qtwebengine && git ls-tree HEAD src/3rdparty
# 160000 commit e0fd3a5d3ce79d43dee6e0bad16a71123d9a14b3    src/3rdparty
```

Com esse hash, busca-se apenas a subárvore necessária:

```bash
mkdir chromium && cd chromium && git init
git remote add origin https://code.qt.io/qt/qtwebengine-chromium.git
git sparse-checkout init --cone
git sparse-checkout set \
  chromium/third_party/libxml \
  chromium/third_party/blink/renderer/core/xml
git fetch --depth 1 origin e0fd3a5d3ce79d43dee6e0bad16a71123d9a14b3
git checkout FETCH_HEAD
```

| | |
|---|---|
| Tag do Qt WebEngine | `v5.15.12-lts` → `4ea03a0affbfd6ff36a7defd391b7ca139d18c8e` |
| Commit do Chromium | `e0fd3a5d3ce79d43dee6e0bad16a71123d9a14b3`, de 09/12/2022 |
| Base | Chromium 87.0.4280.144, com patches até 108.0.5359.94 |

O hash da tag confere com o arquivo `.tag` presente no tarball de release, o que confirma que o código analisado corresponde exatamente à versão 5.15.12.

> [!NOTE]
> A branch `87-based` continuou recebendo *backports* depois da 5.15.12. Em seu estado atual, o libxml2 já foi atualizado para a 2.11.0, que **não** é afetada. Analisar a branch em vez do commit fixado levaria a uma conclusão correta pelo motivo errado.

## Conteúdo

```text
SF-529088_Projeto_libxml2/
├── chromium/blink/xml/        Código real do Blink (C++), 32 arquivos .cc
└── third_party/libxml/
    ├── BUILD.gn               Evidência: define o que é compilado
    ├── README.chromium        Evidência: versão e modificações aplicadas
    ├── linux/include/libxml/  Evidência: configuração de compilação
    └── src/                   libxml2 real, apenas os 27 arquivos .c compilados
```

O diretório `src/` contém **apenas os arquivos que o `BUILD.gn` efetivamente compila**. Os 22 arquivos excluídos do build não foram copiados, porque o escopo da análise deve ser o escopo da compilação: código que não é compilado não existe no binário e não pode ser alcançado.

## A investigação

### Evidência 1 — o arquivo vulnerável não é compilado

Em `third_party/libxml/BUILD.gn`, a entrada está comentada:

```gn
    #"src/xinclude.c",
    #"src/xlink.c",
    "src/xmlIO.c",
```

Ao todo, 27 arquivos `.c` são compilados e 22 estão comentados, entre eles o `xinclude.c`.

### Evidência 2 — o arquivo foi removido da cópia

O `README.chromium` registra a prática:

```text
Version: 37ebf8a8b2789037792cfc0264b814d742cda2d9
CPEPrefix: cpe:/a:xmlsoft:libxml2:2.9.12
Modifications:
  - Delete various unused files, see chromium/roll.py
```

O `CPEPrefix` é a identificação usada por ferramentas de SCA. Ele declara a versão **2.9.12**, afetada pela CVE.

O `xinclude.c` não está presente no diretório `src/` da cópia do Chromium.

### Evidência 3 — o recurso está desabilitado em todas as plataformas

O `xmlreader.c` **é** compilado e referencia a API de XInclude, o que poderia sugerir que o recurso está ativo. Não está: as referências ficam sob `#ifdef LIBXML_XINCLUDE_ENABLED`, e os três arquivos de configuração de plataforma trazem o mesmo trecho:

```c
#if 0
#define LIBXML_XINCLUDE_ENABLED
#endif
```

Verificado em `win32/`, `mac/` e `linux/`. O recurso está desabilitado em todas.

### Evidência 4 — o Blink nunca chama XInclude

A análise do código real do Blink, em C++, identifica **46 funções do libxml2** chamadas pelo motor de renderização. Nenhuma delas pertence à API de XInclude.

## Metodologia: análise em dois estágios

O ponto de entrada de uma análise deste tipo não é `main`. A aplicação Qt não chama o libxml2 diretamente: quem chama é o Chromium. Além disso, as duas camadas estão em linguagens diferentes.

**Estágio 1 — Blink (C++).** Descobre quais funções do libxml2 o motor de renderização realmente chama:

```bash
python analyzer.py \
  --source "cases/SF-529088_Projeto_libxml2/chromium/blink/xml" \
  --language cpp \
  --cves "data_cves/caseSF-529088_Projeto_libxml2.json" \
  --entry '*' \
  --product Qt6WebEngineCore --version 5.15.12 \
  --output results/SF-529088-blink-vex.json
```

O script [tools/derive_entry_points.py](../../tools/derive_entry_points.py) automatiza esse estágio e grava o resultado, de modo que a lista seja reproduzível e não um dado escrito à mão:

```bash
python tools/derive_entry_points.py \
  --consumer cases/SF-529088_Projeto_libxml2/chromium/blink/xml \
  --consumer-language cpp \
  --library cases/SF-529088_Projeto_libxml2/third_party/libxml \
  --library-language c \
  --output cases/SF-529088_Projeto_libxml2/entry_points.txt
```

O critério é a interseção entre os nomes chamados pelo Blink e os nomes efetivamente **declarados** na biblioteca. Isso descarta símbolos que não são funções — `xmlFree` e `xmlMalloc`, por exemplo, são ponteiros de função globais definidos em `globals.c`, e não funções — e dispensa qualquer heurística de prefixo, o que faz aparecer chamadas como `valuePush`, do `xpath.c`, que um filtro por `xml*` deixaria de fora.

**Estágio 2 — libxml2 (C).** As 43 funções derivadas passam a ser os pontos de entrada. A lista está em [entry_points.txt](entry_points.txt):

```bash
python analyzer.py \
  --source "cases/SF-529088_Projeto_libxml2/third_party/libxml" \
  --language c \
  --cves "data_cves/caseSF-529088_Projeto_libxml2.json" \
  --entry "$(cat cases/SF-529088_Projeto_libxml2/entry_points.txt)" \
  --product Qt6WebEngineCore --version 5.15.12 \
  --output results/SF-529088-vex.json \
  --manual
```

Isso responde à pergunta correta: *partindo de tudo o que o Chromium chama no libxml2, a função vulnerável é alcançável?*

## Resultado

```text
Estado VEX: NOT_AFFECTED
Justificativa: code_not_present
```

| Campo | Valor |
|---|---|
| Arquivos analisados | 83 |
| Pontos de entrada | 43 |
| `evidence.function_present` | `false` |
| `evidence.absence_confirmed` | `true` |

A ferramenta pergunta ao analista se a ausência é deliberada, pois não consegue distinguir sozinha "removida do build" de "escopo incompleto" — no código, os dois casos são idênticos. As quatro evidências acima sustentam a resposta afirmativa.

`code_not_present` é uma justificativa mais forte que `code_not_reachable`. A segunda afirma que a função existe mas não é chamada; a primeira afirma que ela não existe no produto. É a conclusão correta aqui.

## Licenças

O código em `third_party/libxml/src/` é do projeto libxml2, sob licença MIT — veja `src/Copyright`. O código em `chromium/blink/` é do projeto Chromium, sob licença BSD de 3 cláusulas. Ambos foram incluídos sem modificação, apenas com a seleção de arquivos descrita acima.

## Limites desta conclusão

- vale para o **libxml2 embutido**. O Qt WebEngine aceita `-webengine-system-libxml2`, que em Unix usa o libxml2 do sistema, cuja compilação pode ter o XInclude ativo. Para a `Qt6WebEngineCore.dll` no Windows essa opção não se aplica;
- **a maioria dos arquivos é reconhecida apenas em parte**. O libxml2 usa macros como `LIBXML_ATTR_FORMAT(3,0)` na declaração de funções, e o analisador, que não executa o pré-processador, não reconhece esses trechos. Por isso `evidence.analysis_complete` é `false`. Isso **não afeta esta conclusão**, que se apoia na ausência do arquivo e não em alcançabilidade, mas afetaria uma conclusão baseada em `code_not_reachable`;
- a análise cobre a subárvore XML do Blink, e não todo o Chromium. Outro componente do Chromium poderia, em tese, chamar o libxml2 por outro caminho — embora a Evidência 1 torne isso irrelevante, já que a função não é compilada em nenhuma configuração.
