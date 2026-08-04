# Ponto de entrada em linha de comando da PoC de análise de
# alcançabilidade.
#
# A lógica da análise fica no pacote "vector". Este arquivo cuida apenas
# de interpretar os argumentos, coletar as respostas do analista pelo
# terminal e exibir o resultado.

# Importa o módulo argparse, utilizado para receber argumentos
# informados pela linha de comando.
import argparse

# Importa o módulo sys, utilizado para encerrar o programa com um
# código de saída adequado.
import sys

# Importa as funções que executam e gravam a análise completa.
from vector.analysis import OUTPUT_FORMATS, run_analysis, save_analysis

# Importa a exceção base, usada para tratar todos os erros previstos.
from vector.errors import VectorError

# Importa as linguagens suportadas, usadas para validar o argumento
# informado pelo analista.
from vector.parsers import SUPPORTED_LANGUAGES


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
        answer = input(f"{question} [s/n/d]: ").strip().lower()

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
        if answer in {"d", "desconhecido", "i", "inconclusivo"}:

            # Retorna None.
            return None

        # Informa que a resposta fornecida é inválida.
        print("Resposta inválida. Use s, n ou d.")


# Define a função responsável por coletar os fatores manuais
# de explorabilidade.
#
# Esta função será chamada somente se a função vulnerável
# já tiver sido classificada como alcançável.
def collect_manual_assessment(cve, function_name, path):
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

    # Exibe o caminho encontrado, que ajuda o analista a decidir se o
    # atacante realmente controla a entrada que chega à função.
    if path:
        print(f"Caminho: {' -> '.join(path)}")

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
            mitigation_description = input("Descreva a mitigação: ").strip()

    # Solicita observações adicionais sobre a decisão.
    analyst_notes = input("Observações do analista: ").strip()

    # Retorna os resultados da análise manual.
    return {
        "attacker_input": attacker_input,
        "mitigation_present": mitigation_present,
        "mitigation_description": mitigation_description,
        "analyst_notes": analyst_notes,
    }


# Define a função que pergunta sobre a ausência da função vulnerável.
def confirm_absence(cve, function_name):
    """
    Pergunta ao analista por que a função vulnerável não foi encontrada.

    A ausência tem duas causas possíveis, com conclusões opostas:

    - o trecho foi removido do componente ou excluído da compilação,
      caso em que a vulnerabilidade não se aplica ao produto;
    - o escopo informado não inclui o arquivo que declara a função,
      caso em que a análise está incompleta e não conclui nada.

    A ferramenta não consegue distinguir as duas apenas olhando o
    código, pois nos dois casos a função simplesmente não está lá.

    Retorna True quando a ausência é deliberada, e None caso contrário.
    """

    # Exibe uma linha em branco.
    print()

    # Exibe um separador visual.
    print("=" * 70)

    # Exibe o identificador da vulnerabilidade.
    print(f"Função ausente: {cve}")

    # Exibe a função procurada.
    print(f"Função vulnerável: {function_name}")

    # Explica por que a pergunta está sendo feita.
    print(
        "A função não foi encontrada no código analisado. Isso pode "
        "significar\nque ela foi removida do componente, ou que o "
        "escopo da análise está\nincompleto."
    )

    # Exibe outro separador.
    print("=" * 70)

    # Pergunta se a ausência é deliberada.
    resposta = ask_yes_no_unknown(
        "A ausência é deliberada, ou seja, o trecho foi removido do "
        "componente\nou excluído da compilação?"
    )

    # Converte a resposta em confirmação.
    #
    # Apenas o "sim" confirma a ausência. Tanto o "não" quanto o
    # "desconhecido" deixam a vulnerabilidade em investigação, pois
    # nenhum dos dois sustenta a justificativa code_not_present.
    return True if resposta is True else None


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


# Define a função que exibe o resultado de uma vulnerabilidade.
def print_result(result):

    # Imprime uma linha em branco.
    print()

    # Imprime um separador.
    print("-" * 70)

    # Exibe a CVE analisada.
    print(f"CVE: {result['id']}")

    # Exibe a função vulnerável associada.
    print(f"Função vulnerável: {result['vulnerable_function']}")

    # Obtém as evidências registradas.
    evidence = result["evidence"]

    # Exibe o resultado da análise automática.
    print(f"Alcançável: {evidence['reachable']}")

    # Verifica se foi encontrado um caminho.
    if evidence["call_path"]:

        # Exibe o caminho como uma sequência de funções.
        print(f"Caminho: {' -> '.join(evidence['call_path'])}")

    # Executa quando nenhum caminho foi encontrado.
    else:

        # Informa que não existe caminho.
        print("Caminho: não encontrado")

    # Exibe o estado VEX atribuído.
    print(f"Estado VEX: {result['status']}")

    # Exibe a justificativa VEX.
    print(f"Justificativa: {result['justification']}")

    # Exibe a conclusão da avaliação.
    print(f"Conclusão: {result['detail']}")


# Define a função que monta o interpretador de argumentos.
def build_parser():

    # Cria o analisador dos argumentos de linha de comando.
    parser = argparse.ArgumentParser(
        description=(
            "PoC para análise de alcançabilidade, avaliação "
            "simplificada de explorabilidade e geração de uma "
            "declaração VEX."
        )
    )

    # Adiciona a opção que abre a interface gráfica.
    #
    # Quando esta opção é usada, os demais argumentos são preenchidos
    # pela própria interface e por isso deixam de ser obrigatórios.
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Abre a interface gráfica em vez de usar o terminal.",
    )

    # Adiciona o argumento que informa o código-fonte analisado.
    parser.add_argument(
        "--source",
        help=(
            "Arquivo ou pasta com o código-fonte a ser analisado. "
            "Quando uma pasta é informada, todos os arquivos da "
            "linguagem escolhida são analisados em conjunto."
        ),
    )

    # Adiciona o argumento que informa a linguagem.
    parser.add_argument(
        "--language",
        choices=sorted(SUPPORTED_LANGUAGES),
        help=(
            "Linguagem do código-fonte. Quando omitida, a linguagem "
            "é detectada pela extensão dos arquivos."
        ),
    )

    # Adiciona o argumento que informa o arquivo de CVEs.
    parser.add_argument(
        "--cves",
        help="Arquivo JSON com o mapeamento CVE para função.",
    )

    # Adiciona o argumento que informa o ponto de entrada.
    parser.add_argument(
        "--entry",
        default="main",
        help=(
            "Ponto de entrada da análise. Aceita uma função, várias "
            "separadas por vírgula, ou '*' para usar todas as "
            "candidatas encontradas no código, incluindo as funções "
            "decoradas. Padrão: main."
        ),
    )

    # Adiciona o argumento que informa o nome do produto.
    parser.add_argument(
        "--product",
        help="Nome do produto.",
    )

    # Adiciona o argumento que informa a versão do produto.
    parser.add_argument(
        "--version",
        help="Versão do produto.",
    )

    # Adiciona o argumento que informa o arquivo de saída.
    parser.add_argument(
        "--output",
        help="Arquivo JSON que receberá a declaração VEX.",
    )

    # Adiciona o argumento que informa o formato da saída.
    parser.add_argument(
        "--format",
        choices=list(OUTPUT_FORMATS),
        default="poc",
        help=(
            "Formato da declaração gerada. 'poc' usa o formato próprio "
            "da PoC, que registra as evidências de alcançabilidade. "
            "'cyclonedx' gera um documento CycloneDX 1.6, validável "
            "pelo schema oficial. 'ambos' gera os dois, gravando o "
            "CycloneDX com o sufixo .cdx. Padrão: poc."
        ),
    )

    # Adiciona o argumento que informa a pasta dos grafos.
    parser.add_argument(
        "--graphs",
        default="results/graphs",
        help=(
            "Pasta que receberá os grafos gerados. "
            "Padrão: results/graphs."
        ),
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

    # Retorna o interpretador montado.
    return parser


# Define a função principal do programa.
def main():

    # Monta o interpretador de argumentos.
    parser = build_parser()

    # Processa os argumentos fornecidos pelo usuário.
    args = parser.parse_args()

    # Verifica se o analista pediu a interface gráfica.
    if args.gui:

        # Importa a interface apenas quando ela é solicitada.
        #
        # A importação tardia evita exigir o tkinter em execuções
        # feitas apenas pelo terminal, como em um servidor sem
        # ambiente gráfico.
        from vector.gui import launch

        # Abre a interface e encerra o programa quando ela é fechada.
        return launch()

    # Define os argumentos obrigatórios no modo de linha de comando.
    required_arguments = ("source", "cves", "product", "version", "output")

    # Seleciona os argumentos obrigatórios que não foram informados.
    missing = [
        f"--{name}"
        for name in required_arguments
        if getattr(args, name) is None
    ]

    # Verifica se algum argumento obrigatório está faltando.
    if missing:

        # Interrompe a execução informando o que falta e lembrando
        # que a interface gráfica é uma alternativa.
        parser.error(
            f"os seguintes argumentos são obrigatórios: "
            f"{', '.join(missing)}. "
            f"Como alternativa, use --gui para informá-los pela "
            f"interface gráfica."
        )

    # Define a forma de coletar a avaliação manual.
    #
    # Quando a opção --manual não é usada, o valor None indica ao
    # motor de análise que o questionário não deve ser executado.
    assessment_callback = None

    # Define a forma de perguntar sobre a ausência da função.
    absence_callback = None

    # Verifica se a análise manual foi solicitada.
    if args.manual:

        # Usa a coleta pelo terminal.
        assessment_callback = collect_manual_assessment

        # Usa a mesma via para a pergunta sobre a ausência.
        absence_callback = confirm_absence

    # Inicia o tratamento dos erros previstos pela PoC.
    try:

        # Executa a análise completa.
        analysis = run_analysis(
            source=args.source,
            cve_file=args.cves,
            entry_point=args.entry,
            product_name=args.product,
            product_version=args.version,
            language=args.language,
            graphs_directory=args.graphs,
            assessment_callback=assessment_callback,
            absence_callback=absence_callback,
            progress_callback=print,
        )

        # Obtém o resultado da análise estática.
        static_analysis = analysis["static_analysis"]

        # Exibe as funções declaradas encontradas.
        print(f"Funções encontradas: {static_analysis.functions}")

        # Exibe o grafo no terminal.
        print_graph(static_analysis.graph)

        # Percorre os resultados por vulnerabilidade.
        for result in analysis["results"]:

            # Exibe o resultado da vulnerabilidade.
            print_result(result)

        # Grava a declaração nos formatos escolhidos.
        written_files = save_analysis(
            analysis,
            args.output,
            args.format,
        )

        # Imprime uma linha em branco.
        print()

        # Imprime um separador.
        print("=" * 70)

        # Percorre os arquivos gravados.
        for written_file in written_files:

            # Informa onde cada declaração foi salva.
            print(f"Declaração VEX salva em: {written_file}")

    # Captura os erros previstos pela PoC.
    except VectorError as error:

        # Exibe a mensagem no fluxo de erro padrão.
        #
        # O traceback é omitido porque a mensagem já descreve o
        # problema em termos compreensíveis ao analista.
        print(f"\nErro: {error}", file=sys.stderr)

        # Encerra o programa indicando falha.
        return 1

    # Captura a interrupção feita pelo analista com Ctrl+C.
    except KeyboardInterrupt:

        # Informa que a análise foi cancelada.
        print("\nAnálise cancelada pelo usuário.", file=sys.stderr)

        # Encerra o programa indicando falha.
        return 1

    # Encerra o programa indicando sucesso.
    return 0


# Verifica se o arquivo está sendo executado diretamente.
#
# Isso impede a execução automática de main() caso analyzer.py
# seja importado por outro módulo.
if __name__ == "__main__":

    # Executa a função principal e encerra o processo com o
    # código de saída devolvido por ela.
    sys.exit(main())
