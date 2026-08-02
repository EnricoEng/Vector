# Implementa a análise de alcançabilidade sobre o grafo de chamadas.
#
# A análise responde a uma única pergunta: existe pelo menos um caminho
# entre o ponto de entrada da aplicação e a função associada à
# vulnerabilidade?

# Importa a exceção utilizada quando o ponto de entrada não existe.
from .errors import EntryPointError


# Define a função responsável por encontrar um caminho
# entre o ponto de entrada e a função vulnerável.
def find_reachability_path(graph, start, target):
    """
    Executa DFS (Depth-First Search / busca em profundidade) e retorna
    um caminho entre start e target.

    Retorno:
        lista com o caminho, caso seja alcançável;
        None, caso não seja alcançável.
    """

    # Inicializa a pilha da busca em profundidade.
    #
    # Cada item contém:
    # - a função atual;
    # - o caminho percorrido até a função.
    stack = [(start, [start])]

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
        if current == target:

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


# Define a função que sugere pontos de entrada prováveis.
def suggest_entry_points(result):
    """
    Sugere funções que podem servir como ponto de entrada.

    O critério é simples: são candidatas as funções declaradas que não
    são chamadas por nenhuma outra função do grafo. Em um grafo de
    chamadas, essas funções são as raízes.

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


# Define a função que valida o ponto de entrada informado.
def validate_entry_point(result, entry_point):
    """
    Verifica se o ponto de entrada existe no grafo de chamadas.

    Levanta EntryPointError com uma mensagem que sugere alternativas,
    o que ajuda o analista a corrigir um nome digitado incorretamente.
    """

    # Verifica se o ponto de entrada está presente no grafo.
    if entry_point in result.graph:

        # Encerra a validação sem erros.
        return

    # Obtém as funções candidatas a ponto de entrada.
    suggestions = suggest_entry_points(result)

    # Monta a mensagem base do erro.
    message = (
        f"O ponto de entrada '{entry_point}' não foi encontrado "
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
