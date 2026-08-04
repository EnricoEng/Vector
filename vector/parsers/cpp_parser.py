# Implementa a análise estática de código C++.
#
# A implementação é compartilhada com o analisador de C, em c_parser.py.
# As duas linguagens produzem os mesmos tipos de nó para o que interessa
# à análise — definições de função e expressões de chamada —, de modo
# que apenas a gramática carregada e as extensões reconhecidas mudam.
#
# Os acréscimos específicos do C++ estão tratados dentro de c_parser.py:
#
# - qualified_identifier, para nomes como Classe::metodo;
# - field_identifier, para nomes de método;
# - destructor_name e operator_name, para destrutores e sobrecargas.
#
# Limitação conhecida: assim como já ocorre com as chamadas por atributo
# em C, a PoC identifica funções pelo último componente do nome. Métodos
# homônimos de classes diferentes são tratados como uma única função, e
# o aviso correspondente é registrado no resultado da análise.

# Importa a implementação compartilhada.
from .c_parser import analyze_tree_sitter


# Define as extensões reconhecidas como código C++.
#
# A extensão .h não aparece aqui porque é ambígua: ela é usada tanto por
# C quanto por C++. Ela permanece associada ao analisador de C, que a
# processa sem dificuldade nos dois casos, já que a gramática de C
# reconhece a maior parte de um cabeçalho comum.
#
# Cabeçalhos declaradamente C++ usam .hpp, .hh ou .hxx e são
# reconhecidos aqui.
CPP_EXTENSIONS = {
    ".cpp",
    ".cc",
    ".cxx",
    ".hpp",
    ".hh",
    ".hxx",
}


# Define a função que analisa um arquivo ou uma pasta de código C++.
def analyze(path):
    """
    Analisa código C++ e retorna um CallGraphResult.

    O caminho informado pode ser um arquivo ou uma pasta. Quando é uma
    pasta, todos os arquivos das extensões reconhecidas são analisados e
    seus grafos são unidos em um único grafo de chamadas.
    """

    # Delega à implementação compartilhada com o analisador de C.
    return analyze_tree_sitter(
        path=path,
        extensions=CPP_EXTENSIONS,
        language="cpp",
        grammar_module="tree_sitter_cpp",
        label="C++",
        description=".cpp, .cc, .cxx, .hpp, .hh ou .hxx",
    )
