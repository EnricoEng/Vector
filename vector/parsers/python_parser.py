# Implementa a análise estática de código Python.
#
# A análise utiliza o módulo ast da biblioteca padrão, que converte o
# código-fonte em uma árvore sintática abstrata sem executá-lo.
#
# O arquivo é percorrido em três passagens, e não em uma só:
#
# 1. coleta os nomes de todas as funções declaradas no projeto;
# 2. coleta variáveis que guardam funções e coleções de funções;
# 3. constrói as arestas do grafo de chamadas.
#
# A separação é necessária porque decidir se uma atribuição como
# "acao = executar" guarda uma função exige conhecer previamente todas
# as funções declaradas, inclusive as de outros arquivos. Uma única
# passagem só enxergaria o que já tivesse sido lido até ali.

# Importa o módulo ast, utilizado para converter código Python
# em uma árvore sintática abstrata, ou Abstract Syntax Tree.
import ast

# Importa Path para obter o nome do módulo a partir do caminho.
from pathlib import Path

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


# Define a função que percorre uma árvore coletando as funções.
def collect_functions(tree):
    """
    Devolve os nomes de todas as funções declaradas na árvore.

    Inclui métodos de classes e funções aninhadas, pois a PoC identifica
    funções apenas pelo nome.
    """

    # Percorre todos os nós da árvore.
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


# Define a função que reúne as importações de um arquivo.
def collect_imports(tree):
    """
    Devolve a tabela de nomes importados por um arquivo.

    A tabela associa o nome utilizado no código ao módulo de origem:

        from executor import run_command   -> {"run_command": "executor"}
        from pacote.util import limpar     -> {"limpar": "util"}

    Ela é usada para desambiguar funções homônimas. Quando duas funções
    com o mesmo nome existem em módulos diferentes, a importação diz
    qual delas o arquivo realmente utiliza.
    """

    # Inicializa a tabela de importações.
    imports = {}

    # Percorre todos os nós da árvore.
    for node in ast.walk(tree):

        # Considera apenas as importações da forma "from X import Y".
        #
        # A forma "import X" não é usada aqui porque ela não traz nomes
        # de função para o espaço do módulo, apenas o próprio módulo.
        if not isinstance(node, ast.ImportFrom):
            continue

        # Ignora importações relativas sem módulo identificado.
        if not node.module:
            continue

        # Usa apenas o último trecho do caminho do módulo, que é o nome
        # do arquivo de origem.
        module = node.module.rsplit(".", 1)[-1]

        # Percorre os nomes importados.
        for alias in node.names:

            # Registra o nome sob o qual ele é utilizado no código.
            imports[alias.asname or alias.name] = module

    # Devolve a tabela construída.
    return imports


# Define a função que devolve o nome do módulo de um arquivo.
def module_name(source_path):
    """
    Devolve o nome do módulo correspondente a um arquivo.

    Corresponde ao nome do arquivo sem a extensão. Dois arquivos com o
    mesmo nome em pastas diferentes produzem o mesmo módulo, limitação
    aceitável para os fins da PoC.
    """

    # Remove o diretório e a extensão do caminho.
    return Path(source_path).stem


# Define a função que extrai os nomes de função de uma expressão.
def function_names_in(node, known_functions):
    """
    Devolve os nomes de função referenciados por uma expressão.

    Reconhece:

    executar                      -> ["executar"]
    [executar, registrar]         -> ["executar", "registrar"]
    {"run": executar}             -> ["executar"]

    Apenas nomes que correspondem a funções declaradas são devolvidos,
    o que evita confundir uma variável comum com uma função.
    """

    # Verifica se a expressão é um nome simples.
    if isinstance(node, ast.Name):

        # Devolve o nome apenas quando ele é uma função conhecida.
        return [node.id] if node.id in known_functions else []

    # Verifica se a expressão é uma lista ou uma tupla.
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):

        # Reúne os nomes de função presentes nos elementos.
        names = []
        for element in node.elts:
            names.extend(function_names_in(element, known_functions))
        return names

    # Verifica se a expressão é um dicionário.
    #
    # É o caso das tabelas de despacho, em que cada chave textual é
    # associada à função que a trata.
    if isinstance(node, ast.Dict):

        # Reúne os nomes de função presentes nos valores.
        names = []
        for value in node.values:
            names.extend(function_names_in(value, known_functions))
        return names

    # Devolve uma lista vazia para as demais expressões.
    return []


# Define a função que coleta variáveis que guardam funções.
def collect_bindings(tree, known_functions):
    """
    Devolve duas tabelas construídas a partir das atribuições:

    - aliases: variável que recebe uma única função;
    - containers: variável que recebe uma coleção de funções.

    Exemplos:

        acao = executar                  -> aliases["acao"] = "executar"
        ROTAS = {"run": executar}         -> containers["ROTAS"] = [...]

    As duas tabelas permitem resolver chamadas feitas por meio da
    variável, como acao() e ROTAS["run"](), que de outro modo não
    seriam associadas a nenhuma função.
    """

    # Inicializa as duas tabelas.
    aliases = {}
    containers = {}

    # Percorre todos os nós da árvore.
    for node in ast.walk(tree):

        # Considera apenas atribuições simples.
        if not isinstance(node, ast.Assign):
            continue

        # Obtém os nomes de função presentes no valor atribuído.
        names = function_names_in(node.value, known_functions)

        # Ignora atribuições que não envolvem funções.
        if not names:
            continue

        # Percorre os destinos da atribuição.
        for target in node.targets:

            # Considera apenas destinos que são nomes simples.
            if not isinstance(target, ast.Name):
                continue

            # Executa quando o valor é uma única função.
            if isinstance(node.value, ast.Name):

                # Registra o apelido da função.
                aliases[target.id] = names[0]

            # Executa quando o valor é uma coleção de funções.
            else:

                # Registra todas as funções da coleção.
                containers[target.id] = names

    # Devolve as duas tabelas.
    return aliases, containers


# Define uma classe responsável por percorrer a árvore sintática
# e construir um grafo simplificado de chamadas entre funções.
class CallGraphVisitor(ast.NodeVisitor):
    """
    Constrói um grafo de chamadas simplificado.

    Reconhece:
    - chamadas diretas, como funcao();
    - chamadas por atributo, como objeto.metodo();
    - chamadas por variável que guarda uma função, como acao();
    - chamadas por tabela de despacho, como ROTAS["run"]();
    - funções passadas como argumento, como registrar(tratador).

    Limitações:
    - não resolve reflexão nem chamadas montadas em tempo de execução;
    - não diferencia funções homônimas de módulos distintos, exceto
      quando a desambiguação por importação consegue fazê-lo.

    As chamadas que não puderam ser resolvidas são registradas em
    result.unresolved, de modo que a conclusão da análise possa levar em
    conta o que ficou fora do alcance da ferramenta.
    """

    # O método __init__ é executado quando um objeto
    # CallGraphVisitor é criado.
    def __init__(
        self,
        result,
        source_path,
        known_functions,
        aliases,
        containers,
        modules_by_name=None,
        imports=None,
    ):

        # Chama o construtor da classe ast.NodeVisitor.
        super().__init__()

        # Armazena, para cada nome de função, os módulos que a declaram.
        self.modules_by_name = modules_by_name or {}

        # Armazena a tabela de importações do arquivo atual.
        self.imports = imports or {}

        # Armazena o nome do módulo correspondente ao arquivo atual.
        self.module = module_name(source_path)

        # Armazena o resultado acumulado da análise.
        #
        # O mesmo objeto é compartilhado por todos os arquivos de um
        # projeto, o que permite unir os grafos de vários arquivos.
        self.result = result

        # Armazena o arquivo que está sendo analisado no momento.
        self.source_path = source_path

        # Armazena os nomes de todas as funções do projeto.
        self.known_functions = known_functions

        # Armazena as variáveis que guardam uma única função.
        self.aliases = aliases

        # Armazena as variáveis que guardam coleções de funções.
        self.containers = containers

        # Inicializa uma pilha para controlar qual função está
        # sendo percorrida durante a análise da AST.
        self.function_stack = []

    # Define o método que resolve um nome em nós do grafo.
    def qualify(self, name):
        """
        Converte um nome de função nos nós de grafo correspondentes.

        Nomes declarados em um único módulo permanecem como estão, o que
        mantém o grafo legível na maioria dos projetos.

        Nomes declarados em módulos diferentes são ambíguos e recebem o
        prefixo do módulo, como "executor.processar". A escolha do
        módulo segue esta ordem:

        1. o módulo de onde o arquivo atual importou o nome;
        2. o próprio módulo atual, quando ele declara a função;
        3. todos os módulos candidatos, quando nada permite decidir.

        O terceiro caso é uma superaproximação: não sendo possível saber
        qual função é chamada, todas são consideradas alcançáveis.
        """

        # Obtém os módulos que declaram esse nome.
        modules = self.modules_by_name.get(name)

        # Devolve o nome inalterado quando ele não é ambíguo.
        if not modules or len(modules) < 2:
            return [name]

        # Verifica se o arquivo importou o nome de um módulo conhecido.
        origin = self.imports.get(name)
        if origin in modules:
            return [f"{origin}.{name}"]

        # Verifica se o próprio módulo atual declara a função.
        if self.module in modules:
            return [f"{self.module}.{name}"]

        # Devolve todos os candidatos quando nada permite decidir.
        return [f"{module}.{name}" for module in sorted(modules)]

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
        #
        # Quando o nome é ambíguo, o nó do grafo recebe o prefixo do
        # módulo, distinguindo funções homônimas de arquivos diferentes.
        modules = self.modules_by_name.get(node.name)
        if modules and len(modules) > 1:
            function_name = f"{self.module}.{node.name}"
        else:
            function_name = node.name

        # Registra a função como declarada neste arquivo.
        self.result.add_declaration(function_name, self.source_path)

        # Verifica se a função possui decorador.
        if node.decorator_list:

            # Registra a função como decorada.
            #
            # Uma função decorada costuma ser registrada em um framework
            # e chamada por ele, e não pelo código analisado. Por isso
            # ela passa a ser tratada como ponto de entrada adicional.
            self.result.mark_decorated(function_name)

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
        """

        # Obtém o nome da função que contém a chamada.
        caller = self.current_function

        # Processa a chamada somente quando ela ocorre dentro de uma
        # função, pois só nesse caso existe um chamador a registrar.
        if caller is not None:

            # Resolve a expressão chamada em uma lista de funções.
            #
            # A lista possui mais de um item quando a chamada é feita
            # por uma tabela de despacho, situação em que qualquer uma
            # das funções da tabela pode ser executada.
            callees = self.resolve_call(node.func, caller)

            # Registra cada função identificada, resolvendo os nomes
            # ambíguos para o módulo correto.
            for callee in callees:
                for node_name in self.qualify(callee):
                    self.result.add_call(caller, node_name)

            # Registra as funções passadas como argumento.
            #
            # Uma função entregue a outra pode ser chamada depois, em um
            # momento que a análise estática não consegue determinar.
            self.record_arguments(node, caller)

        # Continua percorrendo os elementos internos da chamada.
        # Isso é necessário para identificar chamadas aninhadas,
        # como primeira(segunda()).
        self.generic_visit(node)

    # Define o método que registra funções passadas como argumento.
    def record_arguments(self, node, caller):
        """
        Cria arestas para as funções entregues como argumento.

        Exemplo:

            registrar(tratador)

        A chamada registra tratador em algum lugar para executá-lo
        depois. A aresta é criada porque a execução é possível, ainda
        que o momento não seja conhecido.
        """

        # Reúne os argumentos posicionais e os nomeados.
        arguments = list(node.args) + [
            keyword.value for keyword in node.keywords
        ]

        # Percorre os argumentos da chamada.
        for argument in arguments:

            # Obtém os nomes de função presentes no argumento.
            for name in function_names_in(
                argument,
                self.known_functions,
            ):

                # Registra a relação como referência, e não como
                # chamada direta.
                for node_name in self.qualify(name):
                    self.result.add_reference(caller, node_name)

    # Define o método que resolve a expressão chamada.
    def resolve_call(self, node, caller):
        """
        Devolve a lista de funções que uma expressão pode chamar.

        Retorna uma lista vazia quando a expressão não pôde ser
        resolvida, registrando o trecho em result.unresolved.
        """

        # Verifica se a chamada é feita diretamente pelo nome.
        #
        # Exemplo: process()
        if isinstance(node, ast.Name):

            # Verifica se o nome é uma variável que guarda uma função.
            if node.id in self.aliases:

                # Resolve para a função guardada na variável.
                return [self.aliases[node.id]]

            # Verifica se o nome é uma coleção de funções chamada
            # diretamente, situação incomum mas possível.
            if node.id in self.containers:

                # Resolve para todas as funções da coleção.
                return list(self.containers[node.id])

            # Retorna o identificador da função.
            return [node.id]

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
            return [node.attr]

        # Verifica se a chamada é feita por índice.
        #
        # Exemplo: ROTAS["run"](requisicao)
        if isinstance(node, ast.Subscript):

            # Obtém a expressão que está sendo indexada.
            container = node.value

            # Verifica se é uma variável conhecida que guarda funções.
            if (
                isinstance(container, ast.Name)
                and container.id in self.containers
            ):

                # Resolve para todas as funções da coleção.
                #
                # A chave usada no índice não é avaliada, pois pode ser
                # calculada em tempo de execução. Todas as funções da
                # tabela são consideradas alcançáveis.
                return list(self.containers[container.id])

            # Registra que a chamada não pôde ser resolvida.
            self.result.add_unresolved(
                caller,
                f"linha {node.lineno}: chamada por índice em uma "
                f"coleção cujo conteúdo não foi identificado",
            )

            # Devolve uma lista vazia.
            return []

        # Registra que a estrutura da chamada não é suportada.
        #
        # É o caso de chamadas cujo alvo é o resultado de outra
        # expressão, como obter_tratador()().
        self.result.add_unresolved(
            caller,
            f"linha {getattr(node, 'lineno', 0)}: chamada a partir de "
            f"uma expressão ({type(node).__name__}) que a análise não "
            f"resolve",
        )

        # Devolve uma lista vazia.
        return []


# Define a função que analisa um único arquivo Python.
def parse_file(source_path):
    """
    Lê e converte um arquivo Python em árvore sintática.

    Levanta ParseError quando o arquivo possui erro de sintaxe.
    """

    # Lê o conteúdo do arquivo.
    source = read_source_text(source_path)

    # Inicia o tratamento de possíveis erros de sintaxe.
    try:

        # Converte o código-fonte em uma árvore sintática abstrata.
        return ast.parse(source, filename=str(source_path))

    # Captura erros de sintaxe encontrados no código analisado.
    #
    # ValueError é capturado junto porque o ast levanta esse erro em
    # situações como a presença de um byte nulo no arquivo.
    except (SyntaxError, ValueError) as error:

        # Converte o erro em uma exceção prevista pela PoC.
        raise ParseError(
            f"Erro de sintaxe em {source_path}: {error}"
        ) from error


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

    # Inicializa a lista de árvores já convertidas.
    trees = []

    # Primeira leitura: converte cada arquivo em árvore sintática.
    for source_file in source_files:

        # Inicia o tratamento de erros individuais.
        try:

            # Converte o arquivo em árvore.
            trees.append((source_file, parse_file(source_file)))

        # Captura erros previstos e também erros de leitura do arquivo.
        except (ParseError, OSError) as error:

            # Registra a falha sem interromper a análise dos demais
            # arquivos. Isso é importante ao analisar um projeto
            # inteiro, em que um arquivo quebrado não deve impedir
            # a avaliação de todo o restante.
            result.add_failure(source_file, str(error))

    # Verifica se todos os arquivos falharam.
    if not trees:

        # Interrompe a execução, pois não há grafo para analisar.
        raise ParseError(
            f"Nenhum arquivo Python pôde ser analisado em: {path}"
        )

    # Primeira passagem: reúne os nomes de todas as funções do projeto.
    #
    # A coleta abrange todos os arquivos antes de qualquer aresta ser
    # criada, o que permite reconhecer referências a funções declaradas
    # em outros módulos.
    known_functions = set()

    # Registra também em quais módulos cada nome é declarado, o que
    # permite identificar os nomes ambíguos.
    modules_by_name = {}

    # Percorre as árvores já convertidas.
    for source_file, tree in trees:

        # Obtém as funções declaradas no arquivo.
        declared = collect_functions(tree)

        # Acrescenta os nomes ao conjunto geral.
        known_functions.update(declared)

        # Obtém o nome do módulo correspondente ao arquivo.
        module = module_name(source_file)

        # Associa cada nome ao módulo que o declara.
        for name in declared:
            modules_by_name.setdefault(name, set()).add(module)

    # Segunda passagem: reúne as variáveis que guardam funções.
    aliases = {}
    containers = {}
    for _, tree in trees:
        file_aliases, file_containers = collect_bindings(
            tree,
            known_functions,
        )
        aliases.update(file_aliases)
        containers.update(file_containers)

    # Terceira passagem: constrói as arestas do grafo.
    for source_file, tree in trees:

        # Cria o visitante responsável por montar o grafo.
        #
        # A tabela de importações é lida por arquivo, pois cada um
        # importa de módulos diferentes.
        visitor = CallGraphVisitor(
            result,
            source_file,
            known_functions,
            aliases,
            containers,
            modules_by_name,
            collect_imports(tree),
        )

        # Percorre a árvore sintática.
        visitor.visit(tree)

        # Registra o arquivo como analisado com sucesso.
        result.sources.append(str(source_file))

    # Retorna o resultado da análise estática.
    return result
