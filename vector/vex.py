# Implementa a classificação das vulnerabilidades e a geração da
# declaração VEX simplificada.
#
# O documento produzido não implementa integralmente CSAF, OpenVEX
# ou CycloneDX. É um artefato experimental da PoC.

# Importa o módulo json, utilizado para ler os dados das CVEs
# e gravar a declaração VEX simplificada.
import json

# Importa datetime para obter a data da análise e timezone
# para registrar o horário em UTC.
from datetime import datetime, timezone

# Importa Path, que facilita a manipulação de caminhos de arquivos
# de forma independente do sistema operacional.
from pathlib import Path

# Importa as exceções previstas pela PoC.
from .errors import CveFileError, SourceError


# Define uma função para carregar um arquivo JSON.
def load_json(file_path):

    # Converte o caminho em um objeto Path.
    file_path = Path(file_path)

    # Inicia o tratamento dos erros de leitura.
    try:

        # Abre o arquivo e converte o conteúdo JSON em objetos Python.
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    # Captura a ausência do arquivo.
    except FileNotFoundError as error:

        # Interrompe a execução informando o caminho inválido.
        raise SourceError(
            f"Arquivo não encontrado: {file_path}"
        ) from error

    # Captura o conteúdo que não é um JSON válido.
    except json.JSONDecodeError as error:

        # Interrompe a execução indicando a linha do problema.
        raise CveFileError(
            f"O arquivo {file_path} não contém um JSON válido. "
            f"Erro na linha {error.lineno}, coluna {error.colno}: "
            f"{error.msg}"
        ) from error


# Define a função que valida o arquivo de mapeamento CVE para função.
def load_cve_file(file_path):
    """
    Carrega e valida o arquivo JSON que mapeia CVEs para funções.

    O formato esperado é:

    {
        "vulnerabilities": [
            {
                "id": "CVE-POC-0001",
                "component": "biblioteca-exemplo",
                "component_version": "1.0.0",
                "function": "vulnerable_function"
            }
        ]
    }

    A validação existe porque um arquivo malformado produziria um erro
    obscuro no meio da análise. Verificar o formato antes de começar
    permite exibir uma mensagem clara ao analista.
    """

    # Carrega o conteúdo do arquivo.
    data = load_json(file_path)

    # Verifica se o conteúdo é um objeto JSON.
    if not isinstance(data, dict):

        # Interrompe a execução informando o formato esperado.
        raise CveFileError(
            f"O arquivo {file_path} deveria conter um objeto JSON "
            f"com a chave 'vulnerabilities'."
        )

    # Obtém a lista de vulnerabilidades.
    vulnerabilities = data.get("vulnerabilities")

    # Verifica se a chave existe e contém uma lista.
    if not isinstance(vulnerabilities, list):

        # Interrompe a execução informando a chave ausente ou inválida.
        raise CveFileError(
            f"O arquivo {file_path} precisa conter a chave "
            f"'vulnerabilities' com uma lista de vulnerabilidades."
        )

    # Verifica se a lista possui pelo menos um item.
    if not vulnerabilities:

        # Interrompe a execução, pois não há o que analisar.
        raise CveFileError(
            f"A lista 'vulnerabilities' do arquivo {file_path} "
            f"está vazia."
        )

    # Percorre as vulnerabilidades informadas, numerando a partir de 1.
    for position, entry in enumerate(vulnerabilities, start=1):

        # Verifica se o item é um objeto JSON.
        if not isinstance(entry, dict):

            # Interrompe a execução indicando a posição do problema.
            raise CveFileError(
                f"A vulnerabilidade na posição {position} do arquivo "
                f"{file_path} deveria ser um objeto JSON."
            )

        # Percorre os campos obrigatórios.
        for required_field in ("id", "function"):

            # Verifica se o campo está presente e preenchido.
            if not entry.get(required_field):

                # Interrompe a execução indicando o campo ausente.
                raise CveFileError(
                    f"A vulnerabilidade na posição {position} do "
                    f"arquivo {file_path} não informa o campo "
                    f"obrigatório '{required_field}'."
                )

    # Retorna a lista já validada.
    return vulnerabilities


# Define a função responsável por classificar a vulnerabilidade.
def classify_vulnerability(
    reachable,
    assessment=None,
    analysis_complete=True,
):
    """
    Classifica uma vulnerabilidade usando a seguinte lógica:

    0. Não alcançável, mas a análise não compreendeu todo o código
       percorrido: UNDER_INVESTIGATION / in_triage.

    1. Não alcançável e análise completa:
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

        # Verifica se a análise deixou trechos sem compreender.
        #
        # A justificativa code_not_reachable é uma afirmação forte: ela
        # sustenta que a função vulnerável não pode ser executada. Essa
        # afirmação só é legítima quando a ferramenta compreendeu todas
        # as chamadas do trecho percorrido.
        #
        # Havendo qualquer chamada não resolvida no alcance, a ausência
        # de caminho pode ser apenas um limite da análise, e não uma
        # propriedade do programa. Nesse caso a vulnerabilidade fica em
        # investigação, e não é declarada como não afetante.
        if not analysis_complete:

            # Mantém a vulnerabilidade em investigação.
            return {
                "product_status": "UNDER_INVESTIGATION",
                "cyclonedx_state": "in_triage",
                "justification": None,
                "response": [],
                "residual_risk": True,
                "reason": (
                    "Não foi identificado caminho até a função "
                    "vulnerável, mas a análise não conseguiu resolver "
                    "todas as chamadas do trecho percorrido. A "
                    "ausência de caminho pode ser um limite da "
                    "ferramenta, e não uma propriedade do programa."
                ),
            }

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
    language="python",
    analyzed_files=None,
    analysis_warnings=None,
):
    """
    Produz uma declaração VEX simplificada.

    O documento não implementa integralmente CSAF, OpenVEX
    ou CycloneDX. É um artefato experimental da PoC.

    Os campos "language", "analyzed_files" e "analysis_warnings" foram
    acrescentados para registrar o escopo real da análise. Isso importa
    porque a PoC passou a aceitar pastas inteiras: sem esse registro,
    não seria possível saber quantos arquivos sustentam a conclusão nem
    se algum deles foi analisado apenas em parte.
    """

    # Obtém a data e a hora atuais utilizando o fuso UTC.
    timestamp = datetime.now(timezone.utc).isoformat()

    # Retorna a estrutura da declaração VEX.
    return {
        "document": {
            "format": "VEX-SIMPLIFIED-POC",
            "version": "1.1",
            "author": "Reachability Analysis PoC",
            "timestamp": timestamp,
        },
        "product": {
            "name": product_name,
            "version": product_version,
            "source_file": source_file,
            "entry_point": entry_point,
        },
        "analysis_scope": {
            "language": language,
            "analyzed_files": analyzed_files or [],
            "analyzed_file_count": len(analyzed_files or []),
            "warnings": analysis_warnings or [],
        },
        "vulnerabilities": analysis_results,
    }


# Define uma função para salvar dados em JSON.
def save_json(data, output_path):

    # Converte o caminho de saída em um objeto Path.
    output_path = Path(output_path)

    # Inicia o tratamento dos erros de escrita.
    try:

        # Cria os diretórios necessários caso ainda não existam.
        #
        # O caminho do diretório pai pode ser vazio quando o usuário
        # informa apenas um nome de arquivo. Nesse caso, não há
        # diretório a criar.
        if output_path.parent != Path(""):
            output_path.parent.mkdir(parents=True, exist_ok=True)

        # Abre o arquivo de saída no modo de escrita.
        with output_path.open("w", encoding="utf-8") as file:

            # Converte o objeto Python para JSON.
            json.dump(data, file, indent=2, ensure_ascii=False)

    # Captura falhas de permissão e demais erros do sistema de arquivos.
    except OSError as error:

        # Interrompe a execução informando o motivo.
        raise SourceError(
            f"Não foi possível gravar {output_path}: {error}"
        ) from error
