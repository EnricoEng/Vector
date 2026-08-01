import argparse
import ast
import json
from datetime import datetime, timezone
from pathlib import Path


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

    def __init__(self):
        self.graph = {}
        self.functions = set()
        self.function_stack = []

    @property
    def current_function(self):
        if self.function_stack:
            return self.function_stack[-1]
        return None

    def visit_FunctionDef(self, node):
        function_name = node.name

        self.functions.add(function_name)
        self.graph.setdefault(function_name, [])

        self.function_stack.append(function_name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        caller = self.current_function
        callee = self.get_called_function_name(node.func)

        if caller is not None and callee is not None:
            self.graph.setdefault(caller, [])

            if callee not in self.graphself.graph[caller].append(callee)

        self.generic_visit(node)

    @staticmethod
    def get_called_function_name(node):
        """
        Extrai o nome da função chamada.

        Exemplos:
        process()         -> process
        objeto.process()  -> process
        modulo.process()  -> process
        """

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            return node.attr

        return None


def analyze_source(source_path):
    """
    Realiza a análise estática simplificada do código-fonte.
    """

    source_path = Path(source_path)

    with source_path.open("r", encoding="utf-8") as file:
        source = file.read()

    try:
        tree = ast.parse(source, filename=str(source_path))
    except SyntaxError as error:
        raise RuntimeError(
            f"Erro de sintaxe ao analisar {source_path}: {error}"
        ) from error

    visitor = CallGraphVisitor()
    visitor.visit(tree)

    # Inclui no grafo as funções chamadas que não foram declaradas
    # no mesmo arquivo. Isso ajuda a visualizar dependências externas.
    called_functions = {
        called
        for callees in visitor.graph.values()
        for called in callees
    }

    for function_name in called_functions:
        visitor.graph.setdefault(function_name, [])

    return {
        "source": str(source_path),
        "functions": sorted(visitor.functions),
        "graph": visitor.graph,
    }


def find_reachability_path(graph, start, target):
    """
    Executa DFS e retorna um caminho entre start e target.

    Retorno:
        lista com o caminho, caso seja alcançável;
        None, caso não seja alcançável.
    """

    stack = [(start, [start])]
    visited = set()

    while stack:
        current, path = stack.pop()

        if current == target:
            return path

        if current in visited:
            continue

        visited.add(current)

        for neighbor in reversed(graph.get(current, [])):
            if neighbor not in visited:
                stack.append((neighbor, path + [neighbor]))

    return None


def load_json(file_path):
    with Path(file_path).open("r", encoding="utf-8") as file:
        return json.load(file)


def ask_yes_no_unknown(question):
    """
    Entrada manual para fatores de explorabilidade.

    Retorna:
        True    -> sim
        False   -> não
        None    -> desconhecido
    """

    while True:
        answer = input(f"{question} [s/n/d]: ").strip().lower()

        if answer in {"s", "sim"}:
            return True

        if answer in {"n", "nao", "não"}:
            return False

        if answer in {"d", "desconhecido", "i", "inconclusivo"}:
            return None

        print("Resposta inválida. Use s, n ou d.")


def collect_manual_assessment(cve, function_name):
    """
    Coleta manualmente fatores contextuais de explorabilidade.
    """

    print()
    print("=" * 70)
    print(f"Análise manual: {cve}")
    print(f"Função vulnerável: {function_name}")
    print("=" * 70)

    attacker_input = ask_yes_no_unknown(
        "O atacante consegue controlar dados que chegam à função?"
    )

    exposed_entry_point = ask_yes_no_unknown(
        "O caminho é iniciado por uma interface acessível ao atacante?"
    )

    practical_conditions = ask_yes_no_unknown(
        "A exploração é viável em condições operacionais plausíveis?"
    )

    mitigation_present = ask_yes_no_unknown(
        "Existe controle que impeça a exploração?"
    )

    exploitation_confirmed = ask_yes_no_unknown(
        "A vulnerabilidade é considerada explorável após a análise?"
    )

    mitigation_type = None

    if mitigation_present is True:
        print()
        print("Tipos de mitigação:")
        print("1 - Proteção em tempo de execução")
        print("2 - Proteção de perímetro")
        print("3 - Controle compensatório")
        print("4 - Configuração necessária não habilitada")
        print("5 - Ambiente necessário não presente")
        print("6 - Dependência necessária não presente")
        print("7 - Outra")

        mitigation_type = input(
            "Informe o número ou descreva a mitigação: "
        ).strip()

    notes = input("Observações do analista: ").strip()

    return {
        "attacker_input": attacker_input,
        "exposed_entry_point": exposed_entry_point,
        "practical_conditions": practical_conditions,
        "mitigation_present": mitigation_present,
        "mitigation_type": mitigation_type,
        "exploitation_confirmed": exploitation_confirmed,
        "analyst_notes": notes,
    }


def map_mitigation_to_justification(mitigation_type):
    """
    Mapeia a mitigação escolhida para uma justificativa semelhante
    às justificativas utilizadas pelo CycloneDX VEX.
    """

    mapping = {
        "1": "protected_at_runtime",
        "2": "protected_at_perimeter",
        "3": "protected_by_mitigating_control",
        "4": "requires_configuration",
        "5": "requires_environment",
        "6": "requires_dependency",
    }

    return mapping.get(
        mitigation_type,
        "protected_by_mitigating_control",
    )


def classify_vulnerability(reachable, assessment=None):
    """
    Converte as evidências técnicas e a análise manual em uma
    classificação compatível com uma declaração VEX simplificada.
    """

    if not reachable:
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

    if assessment is None:
        return {
            "product_status": "UNDER_INVESTIGATION",
            "cyclonedx_state": "in_triage",
            "justification": None,
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável, mas a análise de "
                "explorabilidade ainda não foi realizada."
            ),
        }

    exploitation_confirmed = assessment.get("exploitation_confirmed")
    mitigation_present = assessment.get("mitigation_present")

    if exploitation_confirmed is True:
        return {
            "product_status": "AFFECTED",
            "cyclonedx_state": "exploitable",
            "justification": None,
            "response": ["update"],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável e a exploração foi "
                "considerada viável no contexto avaliado."
            ),
        }

    if exploitation_confirmed is False and mitigation_present is True:
        mitigation_type = assessment.get("mitigation_type")

        return {
            "product_status": "NOT_AFFECTED",
            "cyclonedx_state": "not_affected",
            "justification": map_mitigation_to_justification(
                mitigation_type
            ),
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável, mas um controle "
                "impede sua exploração no contexto avaliado."
            ),
        }

    if exploitation_confirmed is False:
        return {
            "product_status": "NOT_AFFECTED",
            "cyclonedx_state": "not_affected",
            "justification": "requires_environment",
            "response": [],
            "residual_risk": True,
            "reason": (
                "A função vulnerável é alcançável, mas as condições "
                "necessárias à exploração não estão presentes."
            ),
        }

    return {
        "product_status": "UNDER_INVESTIGATION",
        "cyclonedx_state": "in_triage",
        "justification": None,
        "response": [],
        "residual_risk": True,
        "reason": (
            "Não existem evidências suficientes para concluir se a "
            "vulnerabilidade afeta o produto."
        ),
    }


def create_vex_document(
    product_name,
    product_version,
    source_file,
    entry_point,
    analysis_results,
):
    """
    Produz uma declaração VEX simplificada.

    O documento não pretende implementar integralmente CSAF,
    OpenVEX ou CycloneDX. É um artefato experimental da PoC.
    """

    timestamp = datetime.now(timezone.utc).isoformat()

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


def save_json(data, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


def print_graph(graph):
    print()
    print("Grafo de chamadas")
    print("=" * 70)

    for caller, callees in sorted(graph.items()):
        if callees:
            print(f"{caller} -> {', '.join(callees)}")
        else:
            print(f"{caller} -> []")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PoC para análise de alcançabilidade e geração "
            "de declaração VEX simplificada."
        )
    )

    parser.add_argument(
        "--source",
        required=True,
        help="Arquivo Python a ser analisado.",
    )

    parser.add_argument(
        "--cves",
        required=True,
        help="Arquivo JSON com o mapeamento CVE para função.",
    )

    parser.add_argument(
        "--entry",
        default="main",
        help="Ponto de entrada. Padrão: main.",
    )

    parser.add_argument(
        "--product",
        required=True,
        help="Nome do produto.",
    )

    parser.add_argument(
        "--version",
        required=True,
        help="Versão do produto.",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Arquivo JSON que receberá a declaração VEX.",
    )

    parser.add_argument(
        "--manual",
        action="store_true",
        help=(
            "Solicita análise manual de explorabilidade para "
            "funções alcançáveis."
        ),
    )

    args = parser.parse_args()

    static_analysis = analyze_source(args.source)
    graph = static_analysis["graph"]

    print(f"Arquivo analisado: {args.source}")
    print(f"Funções encontradas: {static_analysis['functions']}")

    print_graph(graph)

    if args.entry not in graph:
        raise RuntimeError(
            f"O ponto de entrada '{args.entry}' não foi encontrado."
        )

    cves = load_json(args.cves)
    analysis_results = []

    for cve_entry in cves["vulnerabilities"]:
        cve_id = cve_entry["id"]
        vulnerable_function = cve_entry["function"]

        path = find_reachability_path(
            graph,
            args.entry,
            vulnerable_function,
        )

        is_reachable = path is not None
        assessment = None

        if is_reachable and args.manual:
            assessment = collect_manual_assessment(
                cve_id,
                vulnerable_function,
            )

        classification = classify_vulnerability(
            is_reachable,
            assessment,
        )

        evidence = {
            "analysis_type": "static_call_graph",
            "entry_point": args.entry,
            "vulnerable_function": vulnerable_function,
            "function_present": vulnerable_function in graph,
            "reachable": is_reachable,
            "call_path": path,
            "manual_assessment": assessment,
        }

        result = {
            "id": cve_id,
            "component": cve_entry.get("component"),
            "component_version": cve_entry.get("component_version"),
            "vulnerable_function": vulnerable_function,
            "status": classification["product_status"],
            "analysis_state": classification["cyclonedx_state"],
            "justification": classification["justification"],
            "response": classification["response"],
            "residual_risk": classification["residual_risk"],
            "detail": classification["reason"],
            "evidence": evidence,
        }

        analysis_results.append(result)

        print()
        print("-" * 70)
        print(f"CVE: {cve_id}")
        print(f"Função vulnerável: {vulnerable_function}")
        print(f"Alcançável: {is_reachable}")

        if path:
            print(f"Caminho: {' -> '.join(path)}")
        else:
            print("Caminho: não encontrado")

        print(f"Estado VEX: {classification['product_status']}")
        print(f"Justificativa: {classification['justification']}")
        print(f"Conclusão: {classification['reason']}")

    vex_document = create_vex_document(
        product_name=args.product,
        product_version=args.version,
        source_file=args.source,
        entry_point=args.entry,
        analysis_results=analysis_results,
    )

    save_json(vex_document, args.output)

    print()
    print("=" * 70)
    print(f"Declaração VEX salva em: {args.output}")


if __name__ == "__main__":
    main()
