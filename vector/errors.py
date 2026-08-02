# Define as exceções utilizadas pela PoC.
#
# O objetivo de concentrar as exceções em um módulo próprio é permitir
# que a interface gráfica e a linha de comando tratem os erros previstos
# de forma controlada, exibindo mensagens compreensíveis ao analista
# em vez de um traceback do Python.


# Define a exceção base da PoC.
#
# Todas as demais exceções herdam desta classe, o que permite capturar
# qualquer erro previsto com um único "except VectorError".
class VectorError(Exception):
    """Erro previsto pela PoC."""


# Define o erro utilizado quando o código-fonte não pode ser lido.
#
# Exemplos:
# - o arquivo informado não existe;
# - o caminho aponta para uma pasta vazia;
# - o arquivo não pode ser decodificado como texto.
class SourceError(VectorError):
    """Erro ao localizar ou ler o código-fonte."""


# Define o erro utilizado quando o código-fonte não pode ser analisado.
#
# Exemplo: o arquivo Python possui erro de sintaxe e por isso não é
# possível construir a árvore sintática abstrata.
class ParseError(VectorError):
    """Erro ao converter o código-fonte em árvore sintática."""


# Define o erro utilizado quando a linguagem informada não é suportada.
#
# A PoC reconhece apenas Python e C.
class LanguageError(VectorError):
    """Linguagem não suportada pela PoC."""


# Define o erro utilizado quando o arquivo de CVEs é inválido.
#
# Exemplos:
# - o arquivo não é um JSON válido;
# - falta a chave "vulnerabilities";
# - uma vulnerabilidade não informa o campo "function".
class CveFileError(VectorError):
    """Erro no arquivo JSON que mapeia CVE para função."""


# Define o erro utilizado quando o ponto de entrada informado
# não existe no grafo de chamadas construído.
class EntryPointError(VectorError):
    """Ponto de entrada não encontrado no código analisado."""


# Define o erro utilizado quando uma dependência opcional não está
# disponível no ambiente.
#
# Exemplos:
# - o pacote tree_sitter_c não foi instalado, impedindo a análise de C;
# - o programa "dot", do Graphviz, não está instalado, impedindo a
#   geração da imagem do grafo.
#
# A ausência do Graphviz não interrompe a análise: a PoC continua e
# apenas deixa de gerar a imagem.
class DependencyError(VectorError):
    """Dependência necessária não está disponível no ambiente."""
