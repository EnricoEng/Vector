# Define a versão da PoC em um módulo próprio.
#
# A versão fica isolada aqui, e não em __init__.py, porque também é
# utilizada por analysis.py ao montar o documento CycloneDX. Como o
# __init__.py importa analysis.py, declarar a versão lá criaria uma
# importação circular.
__version__ = "2.1.0"
