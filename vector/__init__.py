# Pacote da PoC de análise de alcançabilidade.
#
# O pacote reúne as etapas da análise em módulos separados:
#
# - errors.py       exceções previstas pela PoC;
# - parsers/        analisadores de Python e de C;
# - reachability.py busca em profundidade sobre o grafo de chamadas;
# - vex.py          classificação e declaração VEX simplificada;
# - graph_image.py  representação visual do grafo;
# - analysis.py     fluxo completo, usado pela CLI e pela interface;
# - gui.py          interface gráfica escrita com tkinter.
#
# O ponto de entrada em linha de comando permanece em analyzer.py,
# na raiz do projeto.

# Importa as funções que executam e gravam a análise completa.
from .analysis import OUTPUT_FORMATS, run_analysis, save_analysis

# Importa as exceções previstas, permitindo capturá-las com
# "from vector import VectorError".
from .errors import (
    CveFileError,
    DependencyError,
    EntryPointError,
    LanguageError,
    ParseError,
    SourceError,
    VectorError,
)

# Importa a versão da PoC, declarada em um módulo próprio para evitar
# uma importação circular com analysis.py.
from .version import __version__

# Define os nomes exportados pelo pacote.
__all__ = [
    "run_analysis",
    "save_analysis",
    "OUTPUT_FORMATS",
    "VectorError",
    "SourceError",
    "ParseError",
    "LanguageError",
    "CveFileError",
    "EntryPointError",
    "DependencyError",
    "__version__",
]
