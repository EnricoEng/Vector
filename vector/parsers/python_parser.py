# Implementa a análise estática de código Python.
#
# A análise utiliza o módulo ast da biblioteca padrão, que converte o
# código-fonte em uma árvore sintática abstrata sem executá-lo.

# Importa o módulo ast, utilizado para converter código Python
# em uma árvore sintática abstrata, ou Abstract Syntax Tree.
import ast

# Importa as exceções previstas pela PoC.
from ..errors import ParseError, SourceError

# Importa a estrutura de resultado e as funções auxiliares comuns
# aos analisadores.
from .base import (
    CallGraphResult,
    collect_source_files,
    read_source_text,
)


# Define as extensões reconhecidas como código Python.
PYTHON_EXTENSIONS = {".py", ".pyw"}


# Define uma classe responsável por percorrer a árvore sintática
# e construir um grafo simplificado de chamadas entre funções.
class CallGraphVisitor(ast.NodeVisitor):
    """
    Constrói um grafo de chamadas simplificado.

    Limitações:
    - considera chamadas diretas como funcao();
    - considera chamadas por atributo como objeto.metodo();
    - não resolve importações dinamicamente;
    - não resolve reflexão, ponteiros de função ou polimorfismo;
    - não diferencia funções homônimas em módulos diferentes.
    """

    # O método __init__ é executado quando um objeto
    # CallGraphVisitor é criado.
    def __init__(self, result, source_path):

        # Chama o construtor da classe ast.NodeVisitor.
        super().__init__()

        # Armazena o resultado acumulado da análise.
        #
        # O mesmo objeto é compartilhado por todos os arquivos de um
        # projeto, o que permite unir os grafos de vários arquivos.
        self.result = result

        # Armazena o arquivo que está sendo analisado no momento.
        self.source_path = source_path

        # Inicializa uma pilha para controlar qual função está
        # sendo percorrida durante a análise da AST.
        self.function_stack = []

    # Define uma propriedade que retorna o nome da função
    # que está sendo analisada no momento.
    @property
    def current_function(self):

        # Verifica se existe alguma função na pilha.
        if self.function_stack:

            # Retorna a função localizada no topo da pilha.
            return self.function_stack[-1]

        # Retorna None quando a análise não está dentro
        # da declaração de uma função.
        return None

    # Este método é chamado automaticamente pelo ast.NodeVisitor
    # quando uma declaração "def nome_da_funcao()" é encontrada.
    def visit_FunctionDef(self, node):

        # Obtém o nome da função encontrada.
        function_name = node.name

        # Registra a função como declarada neste arquivo.
        self.result.add_declaration(function_name, self.source_path)

        # Adiciona a função atual ao topo da pilha.
        self.function_stack.append(function_name)

        # Percorre os elementos existentes dentro da função,
        # procurando, entre outras coisas, chamadas a outras funções.
        self.generic_visit(node)

        # Remove a função da pilha após terminar sua análise.
        self.function_stack.pop()

    # Este método é chamado quando uma função assíncrona,
    # declarada com "async def", é encontrada.
    def visit_AsyncFunctionDef(self, node):

        # Reutiliza a mesma lógica usada para funções comuns.
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        """
        Processa uma chamada de função encontrada na AST.
        Registra uma relação de chamada no formato:
           função_chamadora -> função_chamada

        Exemplo:
            def main():
                process()

        Nesse caso:
             caller = "main"
             callee = "process"
        """

        # Obtém o nome da função que contém a chamada.
        caller = self.current_function

        # Obtém o nome da função chamada.
        callee = self.get_called_function_name(node.func)

        # Registra a chamada somente quando:
        # a chamada está dentro de uma função;
        # foi possível identificar o nome da função chamada.
        if caller is not None and callee is not None:

            # Registra a relação no grafo compartilhado.
            self.result.add_call(caller, callee)

        # Continua percorrendo os elementos internos da chamada.
        # Isso é necessário para identificar chamadas aninhadas,
        # como primeira(segunda()).
        self.generic_visit(node)

    # Define um método estático porque a operação não depende
    # dos atributos do objeto CallGraphVisitor.
    @staticmethod
    def get_called_function_name(node):
        """
        Extrai o nome da função chamada.

        Exemplos:
        process()         -> process
        objeto.process()  -> process
        modulo.process()  -> process
        """

        # Verifica se a chamada é feita diretamente pelo nome.
        #
        # Exemplo: process()
        if isinstance(node, ast.Name):

            # Retorna o identificador da função.
            return node.id

        # Verifica se a chamada utiliza um atributo.
        #
        # Exemplos:
        # objeto.process()
        # modulo.process()
        if isinstance(node, ast.Attribute):

            # Retorna somente o último elemento da chamada.
            #
            # Dessa forma, objeto.process() é registrado
            # apenas como "process".
            return node.attr

        # Retorna None quando a estrutura da chamada
        # não é suportada pela PoC.
        return None


# Define a função que analisa um único arquivo Python.
def analyze_file(source_path, result):
    """
    Analisa um arquivo Python e acumula o resultado em "result".

    Levanta ParseError quando o arquivo possui erro de sintaxe.
    """

    # Lê o conteúdo do arquivo.
    source = read_source_text(source_path)

    # Inicia o tratamento de possíveis erros de sintaxe.
    try:

        # Converte o código-fonte em uma árvore sintática abstrata.
        tree = ast.parse(source, filename=str(source_path))

    # Captura erros de sintaxe encontrados no código analisado.
    #
    # ValueError é capturado junto porque o ast levanta esse erro em
    # situações como a presença de um byte nulo no arquivo.
    except (SyntaxError, ValueError) as error:

        # Converte o erro em uma exceção prevista pela PoC.
        raise ParseError(
            f"Erro de sintaxe em {source_path}: {error}"
        ) from error

    # Cria o visitante responsável por montar o grafo.
    visitor = CallGraphVisitor(result, source_path)

    # Percorre a árvore sintática.
    visitor.visit(tree)

    # Registra o arquivo como analisado com sucesso.
    result.sources.append(str(source_path))


# Define a função que analisa um arquivo ou uma pasta de código Python.
def analyze(path):
    """
    Analisa código Python e retorna um CallGraphResult.

    O caminho informado pode ser um arquivo ou uma pasta. Quando é uma
    pasta, todos os arquivos .py encontrados são analisados e seus
    grafos são unidos em um único grafo de chamadas.
    """

    # Localiza os arquivos que devem ser analisados.
    source_files = collect_source_files(path, PYTHON_EXTENSIONS)

    # Verifica se algum arquivo foi encontrado.
    if not source_files:

        # Interrompe a análise informando o motivo.
        raise SourceError(
            f"Nenhum arquivo Python (.py) encontrado em: {path}"
        )

    # Cria a estrutura que acumulará o resultado da análise.
    result = CallGraphResult(language="python")

    # Percorre os arquivos encontrados.
    for source_file in source_files:

        # Inicia o tratamento de erros individuais.
        try:

            # Analisa o arquivo atual.
            analyze_file(source_file, result)

        # Captura erros previstos e também erros de leitura do arquivo.
        except (ParseError, OSError) as error:

            # Registra a falha sem interromper a análise dos demais
            # arquivos. Isso é importante ao analisar um projeto
            # inteiro, em que um arquivo quebrado não deve impedir
            # a avaliação de todo o restante.
            result.add_failure(source_file, str(error))

    # Verifica se todos os arquivos falharam.
    if not result.sources:

        # Interrompe a execução, pois não há grafo para analisar.
        raise ParseError(
            f"Nenhum arquivo Python pôde ser analisado em: {path}"
        )

    # Retorna o resultado da análise estática.
    return result
