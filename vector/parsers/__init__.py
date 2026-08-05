# Concentra a seleção do analisador adequado a cada linguagem.
#
# Este módulo é o ponto único em que a PoC decide se um código-fonte
# deve ser tratado como Python, C ou C++. A interface gráfica e a linha
# de comando utilizam apenas as funções daqui, sem precisar conhecer os
# detalhes de cada analisador.

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path

# Importa as exceções previstas pela PoC.
from ..errors import LanguageError, SourceError

# Importa o analisador de C e suas extensões.
from . import c_parser

# Importa o analisador de C++ e suas extensões.
from . import cpp_parser

# Importa o analisador de Python e suas extensões.
from . import python_parser

# Importa a estrutura de resultado e a busca de arquivos.
#
# CallGraphResult é reexportado para facilitar o uso por outros módulos.
from .base import CallGraphResult, collect_source_files


# Define as linguagens suportadas pela PoC.
#
# Cada entrada associa o identificador da linguagem a:
# - label: nome exibido na interface gráfica;
# - extensions: extensões reconhecidas;
# - analyze: função que executa a análise.
SUPPORTED_LANGUAGES = {
    "python": {
        "label": "Python (.py)",
        "extensions": python_parser.PYTHON_EXTENSIONS,
        "analyze": python_parser.analyze,
    },
    "c": {
        "label": "C (.c / .h)",
        "extensions": c_parser.C_EXTENSIONS,
        "analyze": c_parser.analyze,
    },
    "cpp": {
        "label": "C++ (.cpp / .hpp)",
        "extensions": cpp_parser.CPP_EXTENSIONS,
        "analyze": cpp_parser.analyze,
    },
}


# Define a função que descobre a linguagem a partir do caminho.
def detect_language(path):
    """
    Descobre a linguagem de um arquivo ou pasta.

    Para arquivos, a decisão é tomada pela extensão.

    Para pastas, a decisão considera qual linguagem possui mais
    arquivos. Esse critério evita que um único script auxiliar em
    Python faça um projeto em C ser analisado como Python.

    Levanta LanguageError quando nenhuma linguagem é reconhecida.
    """

    # Converte o caminho recebido em um objeto Path.
    path = Path(path)

    # Verifica se o caminho existe.
    if not path.exists():

        # Interrompe a execução informando o caminho inválido.
        raise SourceError(f"Caminho não encontrado: {path}")

    # Executa quando o caminho aponta para um arquivo.
    if path.is_file():

        # Obtém a extensão do arquivo em letras minúsculas.
        suffix = path.suffix.lower()

        # Percorre as linguagens suportadas.
        for language, definition in SUPPORTED_LANGUAGES.items():

            # Verifica se a extensão pertence à linguagem atual.
            if suffix in definition["extensions"]:

                # Retorna o identificador da linguagem encontrada.
                return language

        # Interrompe a execução quando a extensão não é suportada.
        raise LanguageError(
            f"Extensão não suportada: '{suffix}'. "
            f"A PoC analisa Python (.py), C (.c/.h) e "
            f"C++ (.cpp/.cc/.cxx/.hpp/.hh/.hxx)."
        )

    # A partir deste ponto, o caminho aponta para uma pasta.
    #
    # Inicializa o dicionário que contará os arquivos por linguagem.
    counts = {}

    # Percorre as linguagens suportadas.
    for language, definition in SUPPORTED_LANGUAGES.items():

        # Conta quantos arquivos daquela linguagem existem na pasta.
        counts[language] = len(
            collect_source_files(path, definition["extensions"])
        )

    # Obtém a linguagem com o maior número de arquivos.
    best_language = max(counts, key=lambda name: counts[name])

    # Verifica se nenhum arquivo foi encontrado.
    if counts[best_language] == 0:

        # Interrompe a execução informando o motivo.
        raise LanguageError(
            f"Nenhum arquivo Python, C ou C++ encontrado em: {path}"
        )

    # Retorna a linguagem predominante na pasta.
    return best_language


# Define as extensões que mais de uma linguagem utiliza legitimamente.
#
# A extensão .h é usada tanto por C quanto por C++. Ela pertence ao
# conjunto de C, para que cabeçalhos de projetos em C sejam analisados,
# mas encontrá-la em uma pasta de C++ é normal e não indica mistura de
# camadas.
#
# Sem esta ressalva, analisar uma pasta de C++ produziria um aviso de
# "arquivos de C ignorados" que descreveria apenas os próprios
# cabeçalhos daquele código.
AMBIGUOUS_EXTENSIONS = {
    ".h": {"c", "cpp"},
}


# Define a função que conta os arquivos ignorados por escolha de
# linguagem.
def ignored_language_files(path, language):
    """
    Conta os arquivos das demais linguagens presentes no caminho.

    Devolve um dicionário no formato {linguagem: quantidade}, contendo
    apenas as linguagens diferentes da analisada que possuem arquivos.

    A contagem existe porque a PoC analisa uma linguagem por vez. Ao
    apontar a ferramenta para uma pasta que mistura linguagens, os
    arquivos das demais são simplesmente ignorados, sem que nada seja
    dito — e o resultado passa a descrever um escopo que não corresponde
    a nenhuma parte real do produto.

    Um detalhe agrava o problema: a extensão .h pertence ao conjunto de
    C, mas é usada também por projetos em C++. Uma pasta com C++ pode
    ter seus cabeçalhos lidos como C enquanto os arquivos .cc ficam de
    fora, o que torna a fronteira invisível.

    Esse mesmo detalhe exige uma ressalva na contagem. Os arquivos cuja
    extensão é compartilhada entre a linguagem analisada e a outra não
    são contados, pois a sua presença é esperada e não indica mistura
    de camadas. Encontrar .h em uma pasta de C++ é normal; encontrar
    .cc em uma pasta de C não é.
    """

    # Converte o caminho recebido em um objeto Path.
    path = Path(path)

    # Não há mistura possível quando o caminho é um arquivo único.
    if path.is_file():
        return {}

    # Inicializa o dicionário de contagens.
    counts = {}

    # Percorre as linguagens suportadas.
    for name, definition in SUPPORTED_LANGUAGES.items():

        # Ignora a linguagem que está sendo analisada.
        if name == language:
            continue

        # Seleciona as extensões que de fato indicam a outra linguagem.
        #
        # Uma extensão compartilhada com a linguagem analisada é
        # descartada: encontrá-la é esperado e não sinaliza mistura.
        exclusivas = {
            extensao
            for extensao in definition["extensions"]
            if language not in AMBIGUOUS_EXTENSIONS.get(extensao, set())
        }

        # Prossegue apenas quando restou alguma extensão exclusiva.
        if not exclusivas:
            continue

        # Conta os arquivos daquela linguagem presentes na pasta.
        total = len(collect_source_files(path, exclusivas))

        # Registra apenas as linguagens que possuem arquivos.
        if total:
            counts[name] = total

    # Devolve as contagens encontradas.
    return counts


# Define a função que executa a análise estática.
def analyze(path, language=None):
    """
    Analisa um arquivo ou pasta e retorna um CallGraphResult.

    Quando "language" não é informada, a linguagem é descoberta
    automaticamente a partir do caminho. Quando é informada, a escolha
    do analista tem prioridade, o que permite, por exemplo, forçar a
    análise de um arquivo com extensão incomum.
    """

    # Verifica se a linguagem não foi informada.
    if language is None:

        # Descobre a linguagem automaticamente.
        language = detect_language(path)

    # Verifica se a linguagem informada é suportada.
    if language not in SUPPORTED_LANGUAGES:

        # Monta a lista de linguagens válidas para a mensagem de erro.
        valid = ", ".join(sorted(SUPPORTED_LANGUAGES))

        # Interrompe a execução informando as opções válidas.
        raise LanguageError(
            f"Linguagem não suportada: '{language}'. "
            f"Use uma destas: {valid}."
        )

    # Executa o analisador correspondente à linguagem.
    return SUPPORTED_LANGUAGES[language]["analyze"](path)
