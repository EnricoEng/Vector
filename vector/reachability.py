# Implementa a análise de alcançabilidade sobre o grafo de chamadas.
#
# A análise responde a uma única pergunta: existe pelo menos um caminho
# entre o ponto de entrada da aplicação e a função associada à
# vulnerabilidade?

# Importa a exceção utilizada quando o ponto de entrada não existe.
from .errors import EntryPointError


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
