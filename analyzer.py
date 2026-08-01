from graphviz import Digraph

# Importa o módulo argparse, utilizado para receber argumentos
# informados pela linha de comando.
import argparse

# Importa o módulo ast, utilizado para converter código Python
# em uma árvore sintática abstrata, ou Abstract Syntax Tree.
import ast

# Importa o módulo json, utilizado para ler os dados das CVEs
# e gravar a declaração VEX simplificada.
import json

# Importa datetime para obter a data da análise e timezone
# para registrar o horário em UTC.
from datetime import datetime, timezone

# Importa Path, que facilita a manipulação de caminhos de arquivos
# de forma independente do sistema operacional.
from pathlib import Path


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
    def __init__(self):

        # Chama o construtor da classe ast.NodeVisitor.
        super().__init__()

        # Inicializa o dicionário que armazenará o grafo de chamadas.
        #
        # Exemplo:
        #
        # {
        #     "main": ["process"],
        #     "process": ["helper"],
        #     "helper": ["vulnerable"],
        #     "vulnerable": []
        # }
        self.graph = {}

        # Inicializa um conjunto que armazenará as funções
        # declaradas no código-fonte.
        self.functions = set()

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

        # Adiciona o nome da função ao conjunto de funções declaradas.
        self.functions.add(function_name)

        # Adiciona a função ao grafo.
        # Caso a função já exista, setdefault não altera
        # o valor existente.
        self.graph.setdefault(function_name, [])

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
           
            print(f"[DEBUG] Chamada encontrada: {caller} -> {callee}")

            # Garante que a função chamadora exista no grafo.
            self.graph.setdefault(caller, [])

            # Obtém a lista de funções chamadas pelo chamador atual.
            called_functions = self.graph.get(caller, [])

            # Evita registrar a mesma chamada mais de uma vez.
            if callee not in called_functions:
                called_functions.append(callee)

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


# Define a função responsável por analisar um arquivo de código-fonte.
def analyze_source(source_path):
    """
    Realiza a análise estática simplificada do código-fonte.
    """

    # Converte o caminho recebido em um objeto Path.
    source_path = Path(source_path)

    # Abre o arquivo no modo de leitura utilizando UTF-8.
    with source_path.open("r", encoding="utf-8") as file:

        # Lê todo o conteúdo do arquivo.
        source = file.read()

    # Inicia o tratamento de possíveis erros de sintaxe.
    try:

        # Converte o código-fonte em uma árvore sintática abstrata.
        tree = ast.parse(
            source,
            filename=str(source_path),
        )

    # Captura erros de sintaxe encontrados no código analisado.
    except SyntaxError as error:

        # Converte o erro de sintaxe em um erro mais descritivo.
        raise RuntimeError(
            f"Erro de sintaxe ao analisar {source_path}: {error}"
        ) from error

    # Cria o visitante responsável por montar o grafo.
    visitor = CallGraphVisitor()

    # Percorre a árvore sintática.
    visitor.visit(tree)

    # Cria um conjunto contendo todas as funções chamadas,
    # incluindo funções não declaradas no arquivo analisado.
    called_functions = {
        called
        for callees in visitor.graph.values()
        for called in callees
    }

    # Percorre todas as funções chamadas.
    for function_name in called_functions:

        # Adiciona ao grafo as funções chamadas que ainda
        # não possuem um nó próprio.
        #
        # Isso permite visualizar funções externas, como input(),
        # print() e funções importadas.
        visitor.graph.setdefault(function_name, [])

    # Retorna as informações obtidas na análise estática.
    return {
        "source": str(source_path),
        "functions": sorted(visitor.functions),
        "graph": visitor.graph,
    }


# Define a função responsável por encontrar um caminho
# entre o ponto de entrada e a função vulnerável.
def find_reachability_path(graph, start, target):
    """
    Executa DFS (Depth-First Search / busca em profundidade) e retorna um caminho entre start e target.

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


# Define uma função para carregar um arquivo JSON.
def load_json(file_path):

    # Converte o caminho em um objeto Path e abre o arquivo.
    with Path(file_path).open(
        "r",
        encoding="utf-8",
    ) as file:

        # Converte o conteúdo JSON em objetos Python.
        return json.load(file)


# Define uma função para solicitar respostas:
# sim, não ou desconhecido.
def ask_yes_no_unknown(question):
    """
    Retorna:
        True  -> sim;
        False -> não;
        None  -> desconhecido.
    """

    # Repete a pergunta até receber uma resposta válida.
    while True:

        # Exibe a pergunta, remove espaços e converte
        # a resposta para letras minúsculas.
        answer = input(
            f"{question} [s/n/d]: "
        ).strip().lower()

        # Verifica se a resposta representa "sim".
        if answer in {"s", "sim"}:

            # Retorna True.
            return True

        # Verifica se a resposta representa "não".
        if answer in {"n", "nao", "não"}:

            # Retorna False.
            return False

        # Verifica se o analista não possui informações
        # suficientes para responder.
        if answer in {
            "d",
            "desconhecido",
            "i",
            "inconclusivo",
        }:

            # Retorna None.
            return None

        # Informa que a resposta fornecida é inválida.
        print("Resposta inválida. Use s, n ou d.")


# Define a função responsável por coletar os fatores manuais
# de explorabilidade.
#
# Esta função será chamada somente se a função vulnerável
# já tiver sido classificada como alcançável.
def collect_manual_assessment(cve, function_name):
    """
    Coleta dois fatores contextuais:

    1. O atacante controla a entrada?
    2. Existe uma mitigação?

    A pergunta sobre alcançabilidade não é feita porque esse resultado
    já foi obtido automaticamente pelo algoritmo de reachability.
    """

    # Exibe uma linha em branco.
    print()

    # Exibe um separador visual.
    print("=" * 70)

    # Exibe o identificador da vulnerabilidade.
    print(f"Análise manual: {cve}")

    # Exibe a função associada à vulnerabilidade.
    print(f"Função vulnerável: {function_name}")

    # Informa que a função já foi considerada alcançável.
    print("Reachability: a função foi classificada como alcançável.")

    # Exibe outro separador.
    print("=" * 70)

    # Pergunta se o atacante controla a entrada.
    attacker_input = ask_yes_no_unknown(
        "O atacante controla a entrada que chega à função vulnerável?"
    )

    # Inicializa o valor da mitigação como desconhecido.
    mitigation_present = None

    # Inicializa a descrição da mitigação como vazia.
    mitigation_description = None

    # A pergunta sobre mitigação só é necessária quando
    # o atacante controla a entrada.
    if attacker_input is True:

        # Pergunta se existe mitigação que impeça a exploração.
        mitigation_present = ask_yes_no_unknown(
            "Existe mitigação que impeça a exploração?"
        )

        # Se existe mitigação, solicita sua descrição.
        if mitigation_present is True:

            # Solicita ao analista uma descrição textual.
            mitigation_description = input(
                "Descreva a mitigação: "
            ).strip()

    # Solicita observações adicionais sobre a decisão.
    analyst_notes = input(
        "Observações do analista: "
    ).strip()

    # Retorna os resultados da análise manual.
    return {
        "attacker_input": attacker_input,
        "mitigation_present": mitigation_present,
        "mitigation_description": mitigation_description,
        "analyst_notes": analyst_notes,
    }


# Define a função responsável por classificar a vulnerabilidade.
def classify_vulnerability(reachable, assessment=None):
    """
    Classifica uma vulnerabilidade usando a seguinte lógica:

    1. Não alcançável:
       NOT_AFFECTED / code_not_reachable.

    2. Alcançável, mas entrada não controlada:
       NOT_AFFECTED / attacker_controlled_input_not_present.

    3. Alcançável, entrada controlada e mitigação presente:
       NOT_AFFECTED / protected_by_mitigating_control.

    4. Alcançável, entrada controlada e sem mitigação:
       AFFECTED / exploitable.

    5. Informação desconhecida:
       UNDER_INVESTIGATION / in_triage.
    """

    # Verifica o resultado automático da análise de alcançabilidade.
    if not reachable:

        # Retorna o estado correspondente ao código não alcançável.
        return {
            "product_status": "NOT_AFFECTED",
            "cyclonedx_state": "not_affected",
            "justification": "code_not_reachable",
            "response": [],
            "residual_risk": False,
            "reason": (
                "Não foi identificado caminho no grafo de chamadas "
                "entre o ponto de entrada e a função vulnerável."
            ),
        }

    # Verifica se a análise manual não foi executada.
    if assessment is None:

        # Mantém a vulnerabilidade em investigação.
        return {
            "product_status": "UNDER_INVESTIGATION",
            "cyclonedx_state": "in_triage",
            "justification": None,
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável, mas a análise "
                "manual de explorabilidade não foi realizada."
            ),
        }

    # Obtém a resposta sobre o controle da entrada pelo atacante.
    attacker_input = assessment.get("attacker_input")

    # Obtém a resposta sobre a existência de mitigação.
    mitigation_present = assessment.get("mitigation_present")

    # Verifica se o analista não conseguiu determinar
    # se o atacante controla a entrada.
    if attacker_input is None:

        # Mantém a vulnerabilidade em investigação.
        return {
            "product_status": "UNDER_INVESTIGATION",
            "cyclonedx_state": "in_triage",
            "justification": None,
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável, mas não foi possível "
                "determinar se o atacante controla a entrada."
            ),
        }

    # Verifica se o atacante não controla a entrada.
    if attacker_input is False:

        # Classifica a vulnerabilidade como não afetante
        # dentro do modelo simplificado da PoC.
        return {
            "product_status": "NOT_AFFECTED",
            "cyclonedx_state": "not_affected",
            "justification": "attacker_controlled_input_not_present",
            "response": [],
            "residual_risk": False,
            "reason": (
                "A função vulnerável é alcançável, mas o atacante não "
                "controla a entrada que chega à função no contexto "
                "operacional avaliado."
            ),
        }

    # A partir deste ponto, attacker_input é True.
    #
    # Verifica se não foi possível determinar a presença
    # ou ausência de mitigação.
    if mitigation_present is None:

        # Mantém a vulnerabilidade em investigação.
        return {
            "product_status": "UNDER_INVESTIGATION",
            "cyclonedx_state": "in_triage",
            "justification": None,
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável e recebe entrada "
                "controlada pelo atacante, mas não foi possível "
                "determinar se existe uma mitigação efetiva."
            ),
        }

    # Verifica se existe uma mitigação que impeça a exploração.
    if mitigation_present is True:

        # Classifica como não afetado no contexto analisado,
        # registrando que existe risco residual.
        return {
            "product_status": "NOT_AFFECTED",
            "cyclonedx_state": "not_affected",
            "justification": "protected_by_mitigating_control",
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável e recebe entrada "
                "controlada pelo atacante, mas existe uma mitigação "
                "que impede sua exploração no contexto avaliado."
            ),
        }

    # Se chegou até este ponto:
    #
    # - a função é alcançável;
    # - o atacante controla a entrada;
    # - não existe mitigação identificada.
    #
    # Portanto, a vulnerabilidade é classificada como afetante.
    return {
        "product_status": "AFFECTED",
        "cyclonedx_state": "exploitable",
        "justification": None,
        "response": ["update"],
        "residual_risk": True,
        "reason": (
            "A função vulnerável é alcançável, recebe entrada "
            "controlada pelo atacante e não possui mitigação "
            "identificada."
        ),
    }


# Define a função responsável por criar a declaração VEX simplificada.
def create_vex_document(
    product_name,
    product_version,
    source_file,
    entry_point,
    analysis_results,
):
    """
    Produz uma declaração VEX simplificada.

    O documento não implementa integralmente CSAF, OpenVEX
    ou CycloneDX. É um artefato experimental da PoC.
    """

    # Obtém a data e a hora atuais utilizando o fuso UTC.
    timestamp = datetime.now(timezone.utc).isoformat()

    # Retorna a estrutura da declaração VEX.
    return {
        "document": {
            "format": "VEX-SIMPLIFIED-POC",
            "version": "1.0",
            "author": "Reachability Analysis PoC",
            "timestamp": timestamp,
        },
        "product": {
            "name": product_name,
            "version": product_version,
            "source_file": source_file,
            "entry_point": entry_point,
        },
        "vulnerabilities": analysis_results,
    }


# Define a função responsável por salvar dados em JSON.
def save_json(data, output_path):

    # Converte o caminho de saída em um objeto Path.
    output_path = Path(output_path)

    # Cria os diretórios necessários caso ainda não existam.
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Abre o arquivo de saída no modo de escrita.
    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        # Converte o objeto Python para JSON.
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


# Define uma função para exibir o grafo no terminal.
def print_graph(graph):

    # Imprime uma linha em branco.
    print()

    # Imprime o título.
    print("Grafo de chamadas")

    # Imprime um separador.
    print("=" * 70)

    # Percorre o grafo em ordem alfabética.
    for caller, callees in sorted(graph.items()):

        # Verifica se a função chama alguma outra função.
        if callees:

            # Exibe a função chamadora e as funções chamadas.
            print(f"{caller} -> {', '.join(callees)}")
            

        # Executa quando a função não chama outra função.
        else:

            # Exibe uma lista vazia.
            print(f"{caller} -> []")


def generate_call_graph_image(
    graph,
    entry_point,
    vulnerable_function,
    reachability_path,
    cve_id,
    output_directory,
):
    """
    Gera uma representação visual do grafo de chamadas.

    Cores utilizadas:
    - azul: ponto de entrada;
    - vermelho: função vulnerável alcançável;
    - laranja: função vulnerável não alcançável;
    - verde: funções e arestas do caminho encontrado;
    - cinza: demais funções.

    A função gera:
    - um arquivo PNG;
    - um arquivo DOT editável.
    """

    # Converte o diretório de saída em um objeto Path.
    output_directory = Path(output_directory)

    # Cria o diretório caso ainda não exista.
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

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
        fontlk="Arial",
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
        elif (
            function_name == vulnerable_function
            and is_reachable
        ):
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

    # Remove caracteres que possam causar problemas no nome do arquivo.
    safe_cve_id = (
        cve_id
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )

    # Define o caminho do arquivo sem extensão.
    output_base = output_directory / (
        f"{safe_cve_id}_call_graph"
    )

    # Renderiza o grafo.
    #
    # São gerados:
    # - CVE-..._call_graph.png;
    # - CVE-..._call_graph.dot.
    rendered_file = dot.render(
        filename=str(output_base),
        cleanup=False,
    )

    # Exibe o local da imagem criada.
    print(f"Imagem do grafo salva em: {rendered_file}")

    # Retorna o caminho da imagem.
    return rendered_file


# Define a função principal do programa.
def main():

    # Cria o analisador dos argumentos de linha de comando.
    parser = argparse.ArgumentParser(
        description=(
            "PoC para análise de alcançabilidade, avaliação "
            "simplificada de explorabilidade e geração de uma "
            "declaração VEX."
        )
    )

    # Adiciona o argumento que informa o código-fonte analisado.
    parser.add_argument(
        "--source",
        required=True,
        help="Arquivo Python a ser analisado.",
    )

    # Adiciona o argumento que informa o arquivo de CVEs.
    parser.add_argument(
        "--cves",
        required=True,
        help="Arquivo JSON com o mapeamento CVE para função.",
    )

    # Adiciona o argumento que informa o ponto de entrada.
    parser.add_argument(
        "--entry",
        default="main",
        help="Ponto de entrada. Padrão: main.",
    )

    # Adiciona o argumento que informa o nome do produto.
    parser.add_argument(
        "--product",
        required=True,
        help="Nome do produto.",
    )

    # Adiciona o argumento que informa a versão do produto.
    parser.add_argument(
        "--version",
        required=True,
        help="Versão do produto.",
    )

    # Adiciona o argumento que informa o arquivo de saída.
    parser.add_argument(
        "--output",
        required=True,
        help="Arquivo JSON que receberá a declaração VEX.",
    )

    # Adiciona a opção que ativa a análise manual.
    parser.add_argument(
        "--manual",
        action="store_true",
        help=(
            "Solicita análise manual simplificada para "
            "funções vulneráveis alcançáveis."
        ),
    )

    # Processa os argumentos fornecidos pelo usuário.
    args = parser.parse_args()

    # Executa a análise estática do código-fonte.
    static_analysis = analyze_source(args.source)

    # Obtém o grafo de chamadas.
    graph = static_analysis["graph"]

    # Exibe o arquivo analisado.
    print(f"Arquivo analisado: {args.source}")

    # Exibe as funções declaradas encontradas.
    print(
        f"Funções encontradas: "
        f"{static_analysis['functions']}"
    )

    # Exibe o grafo no terminal.
    print_graph(graph)

    # Verifica se o ponto de entrada está presente no grafo.
    if args.entry not in graph:

        # Interrompe a execução quando o ponto de entrada
        # não é encontrado.
        raise RuntimeError(
            f"O ponto de entrada '{args.entry}' não foi encontrado."
        )

    # Carrega o arquivo JSON contendo as CVEs.
    cves = load_json(args.cves)

    # Inicializa a lista de resultados.
    analysis_results = []

    # Percorre as vulnerabilidades presentes no arquivo JSON.
    for cve_entry in cves["vulnerabilities"]:

        # Obtém o identificador da CVE.
        cve_id = cve_entry["id"]

        # Obtém o nome da função vulnerável.
        vulnerable_function = cve_entry["function"]

        # Procura um caminho entre o ponto de entrada
        # e a função vulnerável.
        path = find_reachability_path(
            graph,
            args.entry,
            vulnerable_function,
        )

        # Define a alcançabilidade com base na existência do caminho.
        is_reachable = path is not None

        graph_image = generate_call_graph_image(
            graph=graph,
            entry_point=args.entry,
            vulnerable_function=vulnerable_function,
            reachability_path=path,
            cve_id=cve_id,
            output_directory="results/graphs",
        )

        # Inicializa a avaliação manual como ausente.
        assessment = None

        # Executa o questionário somente se:
        #
        # - a função for alcançável;
        # - a opção --manual estiver ativada.
        if is_reachable and args.manual:

            # Coleta os dois fatores manuais:
            #
            # 1. controle da entrada;
            # 2. existência de mitigação.
            assessment = collect_manual_assessment(
                cve_id,
                vulnerable_function,
            )

        # Classifica a vulnerabilidade.
        classification = classify_vulnerability(
            is_reachable,
            assessment,
        )

        # Cria o registro das evidências utilizadas.
        evidence = {
            "analysis_type": "static_call_graph",
            "entry_point": args.entry,
            "vulnerable_function": vulnerable_function,
            "function_present": vulnerable_function in graph,
            "reachable": is_reachable,
            "call_path": path,
            "manual_assessment": assessment,
            "call_graph_image": str(graph_image),
        }

        # Cria o resultado da vulnerabilidade.
        result = {
            "id": cve_id,
            "component": cve_entry.get("component"),
            "component_version": cve_entry.get(
                "component_version"
            ),
            "vulnerable_function": vulnerable_function,
            "status": classification["product_status"],
            "analysis_state": classification[
                "cyclonedx_state"
            ],
            "justification": classification[
                "justification"
            ],
            "response": classification["response"],
            "residual_risk": classification[
                "residual_risk"
            ],
            "detail": classification["reason"],
            "evidence": evidence,
        }

        # Adiciona o resultado à lista.
        analysis_results.append(result)

        # Imprime uma linha em branco.
        print()

        # Imprime um separador.
        print("-" * 70)

        # Exibe a CVE analisada.
        print(f"CVE: {cve_id}")

        # Exibe a função vulnerável associada.
        print(
            f"Função vulnerável: "
            f"{vulnerable_function}"
        )

        # Exibe o resultado da análise automática.
        print(f"Alcançável: {is_reachable}")

        # Verifica se foi encontrado um caminho.
        if path:

            # Exibe o caminho como uma sequência de funções.
            print(f"Caminho: {' -> '.join(path)}")

        # Executa quando nenhum caminho foi encontrado.
        else:

            # Informa que não existe caminho.
            print("Caminho: não encontrado")

        # Exibe o estado VEX atribuído.
        print(
            f"Estado VEX: "
            f"{classification['product_status']}"
        )

        # Exibe a justificativa VEX.
        print(
            f"Justificativa: "
            f"{classification['justification']}"
        )

        # Exibe a conclusão da avaliação.
        print(
            f"Conclusão: "
            f"{classification['reason']}"
        )

    # Cria a declaração VEX simplificada.
    vex_document = create_vex_document(
        product_name=args.product,
        product_version=args.version,
        source_file=args.source,
        entry_point=args.entry,
        analysis_results=analysis_results,
    )

    # Salva a declaração em um arquivo JSON.
    save_json(
        vex_document,
        args.output,
    )

    # Imprime uma linha em branco.
    print()

    # Imprime um separador.
    print("=" * 70)

    # Informa onde a declaração foi salva.
    print(
        f"Declaração VEX salva em: "
        f"{args.output}"
    )


# Verifica se o arquivo está sendo executado diretamente.
#
# Isso impede a execução automática de main() caso analyzer.py
# seja importado por outro módulo.
if __name__ == "__main__":

    # Executa a função principal.
    main()