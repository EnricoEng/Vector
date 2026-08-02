# Implementa a geração da representação visual do grafo de chamadas.
#
# O pacote graphviz do Python apenas escreve o arquivo DOT e invoca o
# programa externo "dot" para produzir a imagem. Esse programa é
# instalado separadamente e frequentemente está ausente.
#
# Por isso, este módulo separa duas etapas:
#
# 1. gravar o arquivo DOT, que sempre funciona;
# 2. renderizar o PNG, que depende do Graphviz instalado.
#
# Quando o Graphviz não está disponível, a análise continua e apenas a
# imagem deixa de ser gerada. Perder a figura não invalida a conclusão
# sobre alcançabilidade.

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path


# Define a função que verifica se o Graphviz está instalado.
def is_graphviz_available():
    """
    Informa se é possível renderizar imagens.

    Retorna False tanto quando o pacote Python não está instalado
    quanto quando o programa "dot" não está no PATH do sistema.
    """

    # Inicia o tratamento da ausência das dependências.
    try:

        # Importa o pacote Python.
        import graphviz

    # Captura a ausência do pacote.
    except ImportError:

        # Informa que a renderização não é possível.
        return False

    # Verifica se o programa externo está acessível.
    #
    # A função shutil.which procura o executável no PATH do sistema.
    from shutil import which

    # Retorna True apenas quando o programa "dot" foi localizado.
    return which("dot") is not None


# Define a função que monta o grafo visual.
def build_digraph(
    graph,
    entry_point,
    vulnerable_function,
    reachability_path,
    cve_id,
):
    """
    Monta o objeto Digraph que representa o grafo de chamadas.

    Cores utilizadas:
    - azul: ponto de entrada;
    - vermelho: função vulnerável alcançável;
    - laranja: função vulnerável não alcançável;
    - verde: funções e arestas do caminho encontrado;
    - cinza: demais funções.
    """

    # Importa a classe apenas quando ela é realmente necessária.
    #
    # Isso permite que o restante da PoC funcione mesmo em um ambiente
    # sem o pacote graphviz instalado.
    from graphviz import Digraph

    # Indica se a função vulnerável foi alcançada.
    is_reachable = reachability_path is not None

    # Define o resultado apresentado no título.
    if is_reachable:
        analysis_result = "ALCANÇÁVEL"
    else:
        analysis_result = "NÃO ALCANÇÁVEL"

    # Cria um grafo direcionado.
    dot = Digraph(
        name="call_graph",
        comment=f"Grafo de chamadas para {cve_id}",
        format="png",
    )

    # Configurações gerais da imagem.
    dot.attr(
        rankdir="TB",
        bgcolor="white",
        label=(
            f"Grafo de chamadas\n"
            f"{cve_id} | Resultado: {analysis_result}"
        ),
        labelloc="t",
        fontsize="20",
        fontname="Arial",
        pad="0.4",
        nodesep="0.6",
        ranksep="1.0",
    )

    # Configurações padrão dos nós.
    dot.attr(
        "node",
        shape="box",
        style="rounded,filled",
        color="#64748B",
        fillcolor="#F1F5F9",
        fontcolor="#0F172A",
        fontname="Arial",
        fontsize="11",
        margin="0.15",
    )

    # Configurações padrão das arestas.
    dot.attr(
        "edge",
        color="#94A3B8",
        fontname="Arial",
        fontsize="10",
        arrowsize="0.8",
    )

    # Converte o caminho em um conjunto para facilitar as buscas.
    path_nodes = set(reachability_path or [])

    # Cria um conjunto contendo todos os nós do grafo.
    all_nodes = set(graph.keys())

    # Inclui também as funções chamadas.
    for callees in graph.values():
        all_nodes.update(callees)

    # Garante que o ponto de entrada e a função vulnerável
    # apareçam na imagem.
    all_nodes.add(entry_point)
    all_nodes.add(vulnerable_function)

    # Adiciona os nós ao grafo visual.
    for function_name in sorted(all_nodes):

        # Ponto de entrada.
        if function_name == entry_point:
            dot.node(
                function_name,
                label=f"{function_name}\nPonto de entrada",
                fillcolor="#DBEAFE",
                color="#2563EB",
                penwidth="2.5",
            )

        # Função vulnerável alcançável.
        elif function_name == vulnerable_function and is_reachable:
            dot.node(
                function_name,
                label=f"{function_name}\nFunção vulnerável",
                fillcolor="#FEE2E2",
                color="#DC2626",
                fontcolor="#991B1B",
                penwidth="3",
            )

        # Função vulnerável não alcançável.
        elif function_name == vulnerable_function:
            dot.node(
                function_name,
                label=(
                    f"{function_name}\n"
                    f"Função vulnerável não alcançável"
                ),
                fillcolor="#FFEDD5",
                color="#EA580C",
                fontcolor="#9A3412",
                penwidth="3",
            )

        # Função pertencente ao caminho encontrado.
        elif function_name in path_nodes:
            dot.node(
                function_name,
                fillcolor="#DCFCE7",
                color="#16A34A",
                fontcolor="#166534",
                penwidth="2.5",
            )

        # Demais funções.
        else:
            dot.node(function_name)

    # Cria um conjunto com as arestas do caminho alcançável.
    path_edges = set()

    # Verifica se existe um caminho.
    if reachability_path:

        # Percorre pares consecutivos do caminho.
        #
        # Exemplo:
        # ["main", "process", "vulnerable"]
        #
        # produzirá:
        # ("main", "process")
        # ("process", "vulnerable")
        for index in range(len(reachability_path) - 1):
            caller = reachability_path[index]
            callee = reachability_path[index + 1]

            path_edges.add((caller, callee))

    # Adiciona todas as arestas ao grafo.
    for caller, callees in sorted(graph.items()):
        for callee in callees:

            # Destaca as arestas pertencentes ao caminho encontrado.
            if (caller, callee) in path_edges:
                dot.edge(
                    caller,
                    callee,
                    color="#16A34A",
                    penwidth="3",
                    label="caminho alcançável",
                    fontcolor="#166534",
                )

            # Representa normalmente as demais arestas.
            else:
                dot.edge(
                    caller,
                    callee,
                    color="#94A3B8",
                    penwidth="1.5",
                )

    # Retorna o grafo montado.
    return dot


# Define a função que gera os arquivos do grafo.
def generate_call_graph_image(
    graph,
    entry_point,
    vulnerable_function,
    reachability_path,
    cve_id,
    output_directory,
):
    """
    Gera a representação visual do grafo de chamadas.

    A função tenta gerar:
    - um arquivo DOT editável;
    - um arquivo PNG.

    Retorna um dicionário com as chaves:
    - dot_file: caminho do arquivo DOT, ou None;
    - image_file: caminho da imagem, ou None;
    - warning: mensagem explicando por que a imagem não foi gerada.

    A função nunca levanta exceção por causa do Graphviz. A ausência da
    imagem é registrada como aviso para não interromper a análise.
    """

    # Converte o diretório de saída em um objeto Path.
    output_directory = Path(output_directory)

    # Remove caracteres que possam causar problemas no nome do arquivo.
    safe_cve_id = (
        cve_id
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )

    # Inicia o tratamento de erros da geração.
    try:

        # Cria o diretório caso ainda não exista.
        output_directory.mkdir(parents=True, exist_ok=True)

        # Monta o grafo visual.
        dot = build_digraph(
            graph,
            entry_point,
            vulnerable_function,
            reachability_path,
            cve_id,
        )

    # Captura a ausência do pacote graphviz e falhas de escrita.
    except (ImportError, OSError) as error:

        # Retorna o aviso sem interromper a análise.
        return {
            "dot_file": None,
            "image_file": None,
            "warning": (
                f"Não foi possível montar o grafo visual: {error}"
            ),
        }

    # Define o caminho do arquivo sem extensão.
    output_base = output_directory / f"{safe_cve_id}_call_graph"

    # Inicia o tratamento de erros da gravação do arquivo DOT.
    try:

        # Grava o arquivo DOT.
        #
        # Essa etapa não depende do programa externo "dot" e por isso
        # funciona mesmo sem o Graphviz instalado.
        dot_file = Path(f"{output_base}.dot")
        dot_file.write_text(dot.source, encoding="utf-8")

    # Captura falhas de escrita.
    except OSError as error:

        # Retorna o aviso sem interromper a análise.
        return {
            "dot_file": None,
            "image_file": None,
            "warning": (
                f"Não foi possível gravar o arquivo DOT: {error}"
            ),
        }

    # Verifica se o programa externo está disponível.
    if not is_graphviz_available():

        # Retorna apenas o arquivo DOT, explicando como obter a imagem.
        return {
            "dot_file": str(dot_file),
            "image_file": None,
            "warning": (
                "O programa 'dot', do Graphviz, não foi encontrado no "
                "sistema. O arquivo DOT foi gravado, mas a imagem PNG "
                "não pôde ser gerada. Instale o Graphviz em "
                "https://graphviz.org/download/ para obter a imagem."
            ),
        }

    # Inicia o tratamento de erros da renderização.
    try:

        # Renderiza o grafo, produzindo o arquivo PNG.
        rendered_file = dot.render(
            filename=str(output_base),
            cleanup=False,
        )

    # Captura qualquer falha do programa externo.
    #
    # A captura é ampla porque o pacote graphviz define suas próprias
    # exceções, que não podem ser importadas quando o pacote está
    # ausente do ambiente.
    except Exception as error:

        # Retorna o aviso sem interromper a análise.
        return {
            "dot_file": str(dot_file),
            "image_file": None,
            "warning": (
                f"O arquivo DOT foi gravado, mas a renderização da "
                f"imagem falhou: {error}"
            ),
        }

    # Retorna os caminhos dos arquivos gerados.
    return {
        "dot_file": str(dot_file),
        "image_file": str(rendered_file),
        "warning": None,
    }
