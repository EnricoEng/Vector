# Implementa a análise estática de código C.
#
# Diferente do Python, a linguagem C não possui um analisador sintático
# na biblioteca padrão. A PoC utiliza o tree-sitter, um analisador
# incremental que constrói uma árvore sintática concreta.
#
# O tree-sitter foi escolhido por dois motivos:
#
# 1. não exige pré-processamento do arquivo, ou seja, diretivas como
#    #include e #define não precisam ser resolvidas antes da análise;
# 2. é tolerante a erros, produzindo uma árvore parcial mesmo quando
#    parte do arquivo não pode ser reconhecida.
#
# Essa tolerância é importante porque a PoC analisa o código-fonte
# isoladamente, sem os cabeçalhos do sistema e sem as macros expandidas.

# Importa as exceções previstas pela PoC.
from ..errors import DependencyError, ParseError, SourceError

# Importa a estrutura de resultado e as funções auxiliares comuns
# aos analisadores.
from .base import (
    CallGraphResult,
    collect_source_files,
    read_source_text,
)


# Define as extensões reconhecidas como código C.
#
# Os arquivos de cabeçalho são incluídos porque frequentemente contêm
# funções declaradas como "static inline", que fazem parte do código
# efetivamente compilado na aplicação.
C_EXTENSIONS = {".c", ".h"}


# Define os tipos de nó que apenas envolvem o declarador de uma função
# sem alterar o seu nome.
#
# Exemplo:
#
#     static char *helper(const char *s)
#
# Nesse caso, o declarador da função é um pointer_declarator que
# contém, internamente, o function_declarator com o nome "helper".
WRAPPER_DECLARATORS = {
    "pointer_declarator",
    "array_declarator",
    "parenthesized_declarator",
    "init_declarator",
    "attributed_declarator",
}


# Define os tipos de nó que envolvem a expressão chamada sem alterar
# o identificador que interessa à análise.
#
# Exemplos:
#
#     (*ponteiro_de_funcao)(argumento)
#     tabela[indice](argumento)
WRAPPER_EXPRESSIONS = {
    "parenthesized_expression",
    "pointer_expression",
    "subscript_expression",
}


# Define a função responsável por carregar o analisador do tree-sitter.
def load_parser():
    """
    Cria e devolve um analisador tree-sitter configurado para C.

    Levanta DependencyError quando os pacotes necessários não estão
    instalados ou quando as versões instaladas são incompatíveis entre
    si, situação em que o tree-sitter recusa a gramática.
    """

    # Inicia o tratamento da ausência das dependências.
    try:

        # Importa a classe que representa uma gramática e o analisador.
        from tree_sitter import Language, Parser

        # Importa a gramática da linguagem C.
        import tree_sitter_c

    # Captura a ausência de qualquer um dos pacotes.
    except ImportError as error:

        # Converte o erro em uma mensagem que orienta a instalação.
        raise DependencyError(
            "A análise de código C exige os pacotes tree-sitter e "
            "tree-sitter-c. Instale as dependências com:\n"
            "    pip install -r requirements.txt"
        ) from error

    # Inicia o tratamento de incompatibilidade entre as versões.
    try:

        # Carrega a gramática da linguagem C.
        language = Language(tree_sitter_c.language())

        # Cria o analisador já associado à gramática.
        return Parser(language)

    # Captura a incompatibilidade de versão entre tree-sitter
    # e tree-sitter-c.
    #
    # O tree-sitter valida a versão da ABI da gramática e recusa
    # gramáticas mais novas do que a biblioteca instalada.
    except (ValueError, TypeError) as error:

        # Converte o erro em uma mensagem que orienta a correção.
        raise DependencyError(
            "As versões instaladas de tree-sitter e tree-sitter-c são "
            "incompatíveis entre si. Reinstale as versões testadas "
            "com:\n"
            "    pip install -r requirements.txt\n"
            f"Detalhe técnico: {error}"
        ) from error


# Define a função que extrai o texto correspondente a um nó da árvore.
def node_text(node, source_bytes):

    # Recorta os bytes do trecho e converte o resultado em texto.
    #
    # A conversão substitui caracteres inválidos para não interromper
    # a análise por causa de um único byte inesperado.
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


# Define a função que obtém o nome declarado por um declarador.
def declarator_name(node, source_bytes):
    """
    Percorre um declarador até encontrar o nome da função.

    Exemplos e resultados:

    main(void)                    -> main
    *helper(const char *s)        -> helper
    (*callback)(int)              -> callback

    A busca é feita descendo pelos campos da árvore em vez de usar a
    posição dos filhos. Isso é necessário porque os nomes dos parâmetros
    também são identificadores e apareceriam por engano em uma busca
    puramente posicional.
    """

    # Percorre a árvore enquanto houver um nó a examinar.
    while node is not None:

        # Verifica se o nó já é o identificador procurado.
        if node.type == "identifier":

            # Retorna o nome da função.
            return node_text(node, source_bytes)

        # Verifica se o nó é o declarador da função.
        #
        # O campo "declarator" de um function_declarator contém o nome,
        # enquanto o campo "parameters" contém os argumentos.
        if node.type == "function_declarator":

            # Continua a busca apenas pelo campo do nome.
            node = node.child_by_field_name("declarator")

            # Reinicia o laço com o novo nó.
            continue

        # Verifica se o nó apenas envolve o declarador real.
        if node.type in WRAPPER_DECLARATORS:

            # Tenta obter o declarador interno pelo nome do campo.
            inner = node.child_by_field_name("declarator")

            # Executa quando o campo não existe.
            #
            # É o caso do parenthesized_declarator, que não nomeia
            # o filho. Nessa situação, usa-se o primeiro filho nomeado.
            if inner is None:

                # Filtra apenas os filhos nomeados, descartando
                # símbolos como parênteses e asteriscos.
                named_children = [
                    child
                    for child in node.children
                    if child.is_named
                ]

                # Usa o primeiro filho nomeado, quando existir.
                inner = named_children[0] if named_children else None

            # Continua a busca a partir do nó interno.
            node = inner

            # Reinicia o laço com o novo nó.
            continue

        # Interrompe a busca quando o tipo de nó não é reconhecido.
        return None

    # Retorna None quando a árvore terminou sem encontrar o nome.
    return None


# Define a função que obtém o nome da função chamada.
def call_target_name(node, source_bytes):
    """
    Extrai o nome da função chamada por uma expressão.

    Exemplos e resultados:

    process()              -> process
    objeto.processa()      -> processa
    ponteiro->processa()   -> processa
    (*callback)()          -> callback

    Chamadas indiretas por ponteiro de função são registradas pelo nome
    da variável que armazena o ponteiro. A PoC não resolve qual função
    o ponteiro realmente aponta em tempo de execução, o que constitui
    uma limitação conhecida da análise.
    """

    # Percorre a árvore enquanto houver um nó a examinar.
    while node is not None:

        # Verifica se o nó é um identificador simples.
        #
        # Exemplo: process()
        if node.type == "identifier":

            # Retorna o nome da função chamada.
            return node_text(node, source_bytes)

        # Verifica se a chamada acessa um campo de estrutura.
        #
        # Exemplos:
        # objeto.processa()
        # ponteiro->processa()
        if node.type == "field_expression":

            # Obtém o campo acessado, que corresponde ao nome chamado.
            field = node.child_by_field_name("field")

            # Verifica se o campo foi localizado.
            if field is not None:

                # Retorna apenas o nome final da chamada, seguindo o
                # mesmo critério adotado na análise de Python.
                return node_text(field, source_bytes)

            # Interrompe a busca quando o campo não existe.
            return None

        # Verifica se o nó apenas envolve a expressão real.
        if node.type in WRAPPER_EXPRESSIONS:

            # Filtra apenas os filhos nomeados.
            named_children = [
                child
                for child in node.children
                if child.is_named
            ]

            # Verifica se existe algum filho a examinar.
            if not named_children:

                # Interrompe a busca.
                return None

            # Continua a busca pelo primeiro filho nomeado.
            node = named_children[0]

            # Reinicia o laço com o novo nó.
            continue

        # Interrompe a busca quando o tipo de nó não é reconhecido.
        #
        # É o caso de chamadas cujo alvo é o resultado de outra
        # expressão, como obter_callback()().
        return None

    # Retorna None quando a árvore terminou sem encontrar o nome.
    return None


# Define a função que percorre a árvore sintática de um arquivo.
def walk(node, source_bytes, result, source_path, function_stack):
    """
    Percorre a árvore registrando declarações e chamadas de funções.

    A pilha function_stack indica qual função está sendo percorrida,
    seguindo a mesma estratégia utilizada na análise de Python.
    """

    # Verifica se o nó representa a definição de uma função.
    #
    # Apenas definições são consideradas declarações. Protótipos, que
    # aparecem como "declaration", são ignorados porque não possuem
    # corpo e portanto não realizam chamadas.
    if node.type == "function_definition":

        # Obtém o declarador da função.
        declarator = node.child_by_field_name("declarator")

        # Obtém o nome da função a partir do declarador.
        function_name = declarator_name(declarator, source_bytes)

        # Verifica se o nome foi identificado.
        if function_name is not None:

            # Registra a função como declarada neste arquivo.
            result.add_declaration(function_name, source_path)

            # Adiciona a função ao topo da pilha.
            function_stack.append(function_name)

            # Percorre os filhos do nó com a função no contexto.
            for child in node.children:
                walk(
                    child,
                    source_bytes,
                    result,
                    source_path,
                    function_stack,
                )

            # Remove a função da pilha após terminar sua análise.
            function_stack.pop()

            # Encerra o processamento deste nó, pois os filhos
            # já foram percorridos.
            return

    # Verifica se o nó representa uma chamada de função.
    if node.type == "call_expression":

        # Verifica se a chamada ocorre dentro de uma função.
        if function_stack:

            # Obtém o nome da função que contém a chamada.
            caller = function_stack[-1]

            # Obtém a expressão que identifica a função chamada.
            target = node.child_by_field_name("function")

            # Obtém o nome da função chamada.
            callee = call_target_name(target, source_bytes)

            # Registra a chamada quando o nome foi identificado.
            if callee is not None:

                # Registra a relação no grafo compartilhado.
                result.add_call(caller, callee)

    # Percorre os demais filhos do nó.
    #
    # Isso é necessário para identificar chamadas aninhadas,
    # como primeira(segunda()).
    for child in node.children:
        walk(child, source_bytes, result, source_path, function_stack)


# Define a função que analisa um único arquivo C.
def analyze_file(source_path, result, parser):
    """
    Analisa um arquivo C e acumula o resultado em "result".

    Devolve True quando o tree-sitter encontrou trechos que não pôde
    reconhecer, o que indica cobertura parcial do arquivo.
    """

    # Lê o conteúdo do arquivo como texto.
    source = read_source_text(source_path)

    # Converte o texto em bytes, formato exigido pelo tree-sitter.
    source_bytes = source.encode("utf-8")

    # Inicia o tratamento de falhas do analisador.
    try:

        # Constrói a árvore sintática do arquivo.
        tree = parser.parse(source_bytes)

    # Captura falhas inesperadas do tree-sitter.
    except Exception as error:

        # Converte o erro em uma exceção prevista pela PoC.
        raise ParseError(
            f"Não foi possível analisar {source_path}: {error}"
        ) from error

    # Percorre a árvore a partir do nó raiz.
    walk(
        tree.root_node,
        source_bytes,
        result,
        source_path,
        [],
    )

    # Registra o arquivo como analisado com sucesso.
    result.sources.append(str(source_path))

    # Informa se a árvore contém trechos não reconhecidos.
    return tree.root_node.has_error


# Define a função que analisa um arquivo ou uma pasta de código C.
def analyze(path):
    """
    Analisa código C e retorna um CallGraphResult.

    O caminho informado pode ser um arquivo ou uma pasta. Quando é uma
    pasta, todos os arquivos .c e .h encontrados são analisados e seus
    grafos são unidos em um único grafo de chamadas.
    """

    # Localiza os arquivos que devem ser analisados.
    source_files = collect_source_files(path, C_EXTENSIONS)

    # Verifica se algum arquivo foi encontrado.
    if not source_files:

        # Interrompe a análise informando o motivo.
        raise SourceError(
            f"Nenhum arquivo C (.c ou .h) encontrado em: {path}"
        )

    # Cria o analisador do tree-sitter uma única vez.
    #
    # O mesmo analisador é reaproveitado para todos os arquivos,
    # evitando recarregar a gramática a cada arquivo.
    parser = load_parser()

    # Cria a estrutura que acumulará o resultado da análise.
    result = CallGraphResult(language="c")

    # Percorre os arquivos encontrados.
    for source_file in source_files:

        # Inicia o tratamento de erros individuais.
        try:

            # Analisa o arquivo atual.
            has_error = analyze_file(source_file, result, parser)

            # Verifica se o arquivo foi reconhecido apenas em parte.
            if has_error:

                # Registra o aviso sem descartar o que foi analisado.
                #
                # Trechos não reconhecidos são comuns quando o código
                # depende de macros definidas em cabeçalhos ausentes.
                result.add_failure(
                    source_file,
                    "Arquivo analisado parcialmente: há trechos que o "
                    "analisador não reconheceu, possivelmente por "
                    "dependerem de macros ou cabeçalhos ausentes.",
                )

        # Captura erros previstos e também erros de leitura do arquivo.
        except (ParseError, OSError) as error:

            # Registra a falha sem interromper a análise dos demais
            # arquivos.
            result.add_failure(source_file, str(error))

    # Verifica se todos os arquivos falharam.
    if not result.sources:

        # Interrompe a execução, pois não há grafo para analisar.
        raise ParseError(
            f"Nenhum arquivo C pôde ser analisado em: {path}"
        )

    # Retorna o resultado da análise estática.
    return result
