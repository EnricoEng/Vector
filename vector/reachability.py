# Implementa a análise de alcançabilidade sobre o grafo de chamadas.
#
# A análise responde a uma única pergunta: existe pelo menos um caminho
# entre o ponto de entrada da aplicação e a função associada à
# vulnerabilidade?

# Importa Path para comparar os caminhos informados.
from pathlib import Path

# Importa as exceções previstas pela PoC.
from .errors import EntryPointError, SourceError

# Importa o seletor de analisador por linguagem, usado na derivação de
# pontos de entrada a partir do código que consome uma biblioteca.
from .parsers import (
    analyze as analyze_source,
    ignored_language_files,
)


# Define o texto que representa a seleção de todos os pontos de entrada.
ALL_ENTRY_POINTS = "*"


# Define a função que interpreta os pontos de entrada informados.
def parse_entry_points(text, result):
    """
    Converte o valor informado pelo analista em uma lista de funções.

    Formatos aceitos:

    main            uma única função;
    main,servir     várias funções, separadas por vírgula;
    *               todas as candidatas encontradas no código.

    Aplicações reais raramente possuem um único ponto de entrada: cada
    rota de um servidor e cada subcomando de uma ferramenta é um começo
    possível de execução. Analisar apenas um deles subestima o alcance
    da vulnerabilidade.
    """

    # Remove os espaços nas pontas do valor recebido.
    text = (text or "").strip()

    # Verifica se o analista pediu todas as candidatas.
    if text == ALL_ENTRY_POINTS:

        # Devolve as funções sugeridas pelo próprio grafo.
        return suggest_entry_points(result)

    # Separa os nomes informados e descarta os vazios.
    entries = [name.strip() for name in text.split(",") if name.strip()]

    # Devolve a lista, ou o padrão quando nada foi informado.
    return entries or ["main"]


# Define a função responsável por encontrar um caminho
# entre os pontos de entrada e a função vulnerável.
def find_reachability_path(graph, start, target):
    """
    Executa DFS (Depth-First Search / busca em profundidade) e retorna
    um caminho entre start e target.

    O parâmetro start aceita o nome de uma função ou uma lista de nomes.
    Quando recebe vários, a busca parte de todos e devolve o primeiro
    caminho encontrado.

    Retorno:
        lista com o caminho, caso seja alcançável;
        None, caso não seja alcançável.
    """

    # Aceita tanto um nome isolado quanto uma lista de nomes.
    starts = [start] if isinstance(start, str) else list(start)

    # Aceita também um conjunto de alvos, usado quando o nome da função
    # vulnerável é ambíguo e existe em mais de um módulo.
    targets = {target} if isinstance(target, str) else set(target)

    # Inicializa a pilha da busca em profundidade.
    #
    # Cada item contém:
    # - a função atual;
    # - o caminho percorrido até a função.
    #
    # A ordem é invertida para que o primeiro ponto de entrada
    # informado seja explorado primeiro.
    stack = [(name, [name]) for name in reversed(starts)]

    # Inicializa o conjunto de funções já visitadas.
    visited = set()

    # Continua a busca enquanto existirem funções na pilha.
    while stack:

        # Remove o último item da pilha. Last In, First Out
        current, path = stack.pop()

        # Verifica se a função atual é a função vulnerável.
        # Se a função atual for o alvo, retorna imediatamente o caminho.
        # Não é necessário adicionar o alvo ao conjunto visited, pois
        # a busca termina assim que o primeiro caminho é encontrado.
        if current in targets:

            # Retorna o caminho completo encontrado.
            return path

        # Verifica se a função já foi visitada.
        if current in visited:

            # Ignora a função para evitar ciclos infinitos.
            continue

        # Marca a função atual como visitada.
        visited.add(current)

        # Obtém as funções chamadas pela função atual.
        # Se a função não estiver no grafo, utiliza uma lista vazia.
        neighbors = graph.get(current, [])

        # Percorre os vizinhos em ordem reversa.
        # A ordem reversa deixa a exploração mais previsível
        # em relação à ordem das chamadas no código.
        for neighbor in reversed(neighbors):

            # Verifica se a função vizinha ainda não foi visitada.
            if neighbor not in visited:

                # Adiciona a função vizinha à pilha e cria
                # um novo caminho contendo essa função.
                stack.append(
                    (
                        neighbor,
                        path + [neighbor],
                    )
                )

    # Retorna None quando nenhum caminho é encontrado.
    return None


# Define a função que localiza os nós correspondentes a uma função.
def resolve_target(graph, function_name):
    """
    Devolve os nós do grafo que correspondem a um nome de função.

    O arquivo de CVEs informa apenas o nome da função, como
    "vulnerable_function". Quando esse nome é ambíguo, o grafo o
    armazena qualificado pelo módulo, como "executor.vulnerable_function".

    Esta função faz a ponte entre as duas formas: procura o nome exato
    e, não o encontrando, devolve todos os nós qualificados que
    terminam com ele.
    """

    # Devolve o próprio nome quando ele existe no grafo.
    if function_name in graph:
        return [function_name]

    # Monta o sufixo procurado nos nomes qualificados.
    suffix = f".{function_name}"

    # Devolve todos os nós qualificados com esse nome.
    return sorted(
        node for node in graph if node.endswith(suffix)
    )


# Define a função que lista as funções alcançáveis.
def reachable_functions(graph, starts):
    """
    Devolve o conjunto de funções alcançáveis a partir dos pontos de
    entrada informados.
    """

    # Aceita tanto um nome isolado quanto uma lista de nomes.
    starts = [starts] if isinstance(starts, str) else list(starts)

    # Inicializa a pilha com os pontos de entrada.
    stack = list(starts)

    # Inicializa o conjunto de funções já visitadas.
    visited = set()

    # Percorre o grafo enquanto houver funções na pilha.
    while stack:

        # Remove a última função da pilha.
        current = stack.pop()

        # Ignora funções já visitadas.
        if current in visited:
            continue

        # Marca a função como visitada.
        visited.add(current)

        # Empilha as funções chamadas pela função atual.
        stack.extend(graph.get(current, []))

    # Devolve as funções alcançadas.
    return visited


# Define a função que lista as chamadas não compreendidas no alcance.
def unresolved_in_reach(result, starts):
    """
    Devolve as chamadas não resolvidas que estão no trecho do programa
    alcançável a partir dos pontos de entrada.

    Só interessam as que estão dentro do alcance. Uma chamada não
    compreendida em um trecho do código que nunca é executado a partir
    do ponto de entrada não afeta a conclusão.

    Enquanto essa lista não estiver vazia, a análise não pode afirmar
    que a função vulnerável é inalcançável: existe um trecho do programa
    que a ferramenta não conseguiu acompanhar.
    """

    # Obtém as funções alcançáveis a partir dos pontos de entrada.
    reachable = reachable_functions(result.graph, starts)

    # Monta a lista de trechos não compreendidos dentro do alcance.
    return [
        {"function": name, "details": details}
        for name, details in sorted(result.unresolved.items())
        if name in reachable
    ]


# Define a função que sugere pontos de entrada prováveis.
def suggest_entry_points(result):
    """
    Sugere funções que podem servir como ponto de entrada.

    São candidatas:

    1. as funções declaradas que não são chamadas por nenhuma outra
       função do grafo, ou seja, as raízes;
    2. as funções decoradas.

    O segundo critério existe porque uma função decorada é registrada
    em um framework e chamada por ele. Em um servidor web, o tratador
    de uma rota nunca aparece como destino de uma chamada no código da
    aplicação, mas é executado sempre que a rota é acessada. Ignorá-lo
    faria toda a aplicação parecer inalcançável.

    A função "main", quando existe, é colocada no início da lista por
    ser o ponto de entrada convencional em ambas as linguagens.

    Esta lista alimenta a interface gráfica, que a oferece ao analista
    em vez de exigir que ele digite o nome exato da função.
    """

    # Cria um conjunto contendo todas as funções que são chamadas
    # por alguma outra função.
    called = {
        callee
        for callees in result.graph.values()
        for callee in callees
    }

    # Seleciona as funções declaradas que nunca são chamadas.
    roots = [
        name
        for name in result.functions
        if name not in called
    ]

    # Acrescenta as funções decoradas que ainda não estejam na lista.
    for name in result.decorated:
        if name not in roots:
            roots.append(name)

    # Verifica se a função main existe entre as funções declaradas
    # e ainda não está no início da lista.
    if "main" in result.functions and "main" not in roots:

        # Insere main no começo, pois é o ponto de entrada
        # convencional mesmo quando é chamada explicitamente,
        # como ocorre nos casos de teste em Python.
        roots.insert(0, "main")

    # Executa quando main já é uma raiz do grafo.
    elif "main" in roots:

        # Move main para a primeira posição da lista.
        roots.remove("main")
        roots.insert(0, "main")

    # Retorna as funções candidatas a ponto de entrada.
    return roots


# Define a função que valida os pontos de entrada informados.
def validate_entry_points(result, entry_points):
    """
    Verifica se os pontos de entrada existem no grafo de chamadas.

    Levanta EntryPointError com uma mensagem que sugere alternativas,
    o que ajuda o analista a corrigir um nome digitado incorretamente.
    """

    # Aceita tanto um nome isolado quanto uma lista de nomes.
    entry_points = (
        [entry_points]
        if isinstance(entry_points, str)
        else list(entry_points)
    )

    # Verifica se algum ponto de entrada foi informado.
    if not entry_points:

        # Interrompe a execução, pois não há de onde começar a busca.
        raise EntryPointError(
            "Nenhum ponto de entrada foi informado."
        )

    # Seleciona os nomes que não existem no grafo.
    missing = [
        name for name in entry_points if name not in result.graph
    ]

    # Encerra a validação quando todos os nomes existem.
    if not missing:
        return

    # Obtém as funções candidatas a ponto de entrada.
    suggestions = suggest_entry_points(result)

    # Monta a mensagem base do erro, no singular ou no plural.
    if len(missing) == 1:
        message = (
            f"O ponto de entrada '{missing[0]}' não foi encontrado "
            f"no código analisado."
        )
    else:
        nomes = ", ".join(f"'{name}'" for name in missing)
        message = (
            f"Os pontos de entrada {nomes} não foram encontrados "
            f"no código analisado."
        )

    # Verifica se existem sugestões a oferecer.
    if suggestions:

        # Limita a lista às dez primeiras sugestões para não
        # produzir uma mensagem longa demais.
        preview = ", ".join(suggestions[:10])

        # Acrescenta as sugestões à mensagem.
        message += f" Pontos de entrada prováveis: {preview}."

    # Interrompe a execução com a mensagem construída.
    raise EntryPointError(message)


# Define a função que lista os nomes chamados por um código.
def called_names(result):
    """
    Devolve o conjunto de nomes chamados por qualquer função do código.

    Inclui os nomes que não são declarados no próprio código, que são
    justamente os candidatos a pertencer a uma biblioteca externa.
    """

    # Reúne os destinos de todas as arestas do grafo.
    return {
        callee
        for callees in result.graph.values()
        for callee in callees
    }


# Define a função que deriva pontos de entrada a partir do consumidor.
def derive_entry_points(
    consumer,
    library,
    consumer_language=None,
    library_language=None,
):
    """
    Devolve os nomes de função da biblioteca que o consumidor chama.

    Resolve o problema de analisar uma biblioteca isoladamente: nela não
    existe um "main", e toda função pública é um começo possível de
    execução. Usar todas produz uma análise pessimista, que considera
    alcançável qualquer coisa que a biblioteca faça, inclusive o que o
    programa real nunca aciona.

    O critério é a interseção entre dois conjuntos:

    - os nomes chamados em algum ponto do código do consumidor;
    - os nomes efetivamente declarados na biblioteca.

    A interseção evita duas fontes de erro. Nomes chamados pelo
    consumidor que não pertencem à biblioteca, como funções da
    biblioteca padrão, ficam de fora. E funções da biblioteca que o
    consumidor nunca chama também ficam, que é o objetivo.

    As duas camadas costumam estar em linguagens diferentes, como um
    consumidor em C++ que usa uma biblioteca em C. Por isso a linguagem
    de cada lado é informada separadamente.

    Devolve uma tupla com a lista de nomes, o resultado da análise do
    consumidor, o da biblioteca e a lista de avisos, permitindo ao
    chamador relatar os números e os problemas encontrados.
    """

    # Converte os dois caminhos para a forma absoluta.
    #
    # A comparação exige caminhos resolvidos, pois "a/b" e "./a/b/"
    # apontam para o mesmo lugar mas não são iguais como texto.
    consumer_path = Path(consumer).resolve()
    library_path = Path(library).resolve()

    # Recusa a derivação quando os dois caminhos são o mesmo.
    #
    # Cruzar uma pasta consigo mesma produz as chamadas internas da
    # própria biblioteca, e não o que um consumidor externo utiliza. O
    # resultado seria uma lista enorme e sem significado, por isso o
    # caso é tratado como erro e não como aviso.
    if consumer_path == library_path:
        raise SourceError(
            "O consumidor e a biblioteca apontam para a mesma pasta "
            f"({library}). O consumidor deve ser o código que utiliza "
            "a biblioteca, e não a própria biblioteca. Cruzar uma "
            "pasta consigo mesma devolveria apenas as chamadas "
            "internas dela."
        )

    # Analisa o código do consumidor.
    consumer_result = analyze_source(consumer, consumer_language)

    # Analisa o código da biblioteca.
    library_result = analyze_source(library, library_language)

    # Obtém os nomes chamados pelo consumidor.
    chamados = called_names(consumer_result)

    # Obtém os nomes declarados pela biblioteca.
    #
    # A propriedade functions traz apenas as funções declaradas, e não
    # as que a própria biblioteca chama sem declarar. Um ponto de
    # entrada precisa existir de fato no código analisado.
    declarados = set(library_result.functions)

    # Inicializa a lista de avisos.
    warnings = []

    # Verifica se uma das pastas está contida na outra.
    #
    # Não é necessariamente um erro, mas costuma indicar que uma delas
    # aponta para um nível acima do pretendido, o que faz parte do
    # código ser contado dos dois lados.
    if (
        library_path in consumer_path.parents
        or consumer_path in library_path.parents
    ):
        warnings.append(
            "Uma das pastas informadas está contida na outra. Parte do "
            "código pode estar sendo contada tanto como consumidor "
            "quanto como biblioteca, o que infla a lista de pontos de "
            "entrada."
        )

    # Verifica se alguma das duas pastas mistura linguagens.
    #
    # Este é o engano mais provável nesta etapa: apontar a biblioteca
    # para a raiz de um projeto que contém as duas camadas. A análise
    # então lê os cabeçalhos do consumidor como se fossem da
    # biblioteca, e métodos do consumidor passam a aparecer entre os
    # pontos de entrada derivados.
    for rotulo, caminho, resultado in (
        ("do consumidor", consumer, consumer_result),
        ("da biblioteca", library, library_result),
    ):

        # Conta os arquivos das demais linguagens naquela pasta.
        ignorados = ignored_language_files(caminho, resultado.language)

        # Registra o aviso quando existem arquivos de fora.
        if ignorados:
            detalhe = ", ".join(
                f"{quantidade} de {nome}"
                for nome, quantidade in sorted(ignorados.items())
            )
            warnings.append(
                f"A pasta {rotulo} contém arquivos de outras "
                f"linguagens que não foram analisados: {detalhe}. Ela "
                f"foi lida como {resultado.language}. Verifique se o "
                f"caminho aponta para a camada correta, e não para a "
                f"raiz de um projeto que contém as duas."
            )

    # Devolve a interseção, em ordem alfabética.
    return (
        sorted(chamados & declarados),
        consumer_result,
        library_result,
        warnings,
    )
