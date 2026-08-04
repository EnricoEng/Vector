# Implementa a exportação no formato CycloneDX VEX.
#
# Diferente do formato próprio da PoC, definido em vex.py, este módulo
# produz um documento que obedece ao schema oficial do CycloneDX 1.6 e
# pode ser validado e consumido por ferramentas de terceiros, como o
# Dependency-Track.
#
# A conversão não é uma simples troca de nomes de campos. Existem três
# diferenças estruturais entre os dois formatos:
#
# 1. o CycloneDX exige as chaves bomFormat e specVersion na raiz;
# 2. cada vulnerabilidade precisa apontar, em affects[].ref, para um
#    componente declarado no próprio documento;
# 3. os dados da análise de alcançabilidade não possuem campo próprio
#    na especificação e são registrados como propriedades nomeadas.

# Importa o módulo json, utilizado para gravar o documento.
import json

# Importa datetime para registrar o horário da análise em UTC.
from datetime import datetime, timezone

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path

# Importa uuid para gerar o número de série do documento.
import uuid

# Importa a exceção utilizada em falhas de escrita.
from .errors import SourceError


# Define a versão da especificação seguida por este exportador.
SPEC_VERSION = "1.6"


# Define a correspondência entre as justificativas da PoC e os valores
# aceitos pelo CycloneDX.
#
# O campo justification do CycloneDX é um enumerado fechado, com nove
# valores possíveis. Duas das justificativas da PoC já pertencem a esse
# conjunto e são copiadas sem alteração.
#
# A terceira, attacker_controlled_input_not_present, não existe na
# especificação e precisa ser aproximada. O valor escolhido foi
# requires_environment, cuja definição oficial é:
#
#     "Exploitability requires a certain environment which is not
#      present."
#
# A leitura é a seguinte: a exploração exigiria um contexto operacional
# em que dados controlados pelo atacante alcancem a função vulnerável, e
# esse contexto não está presente no ambiente avaliado.
#
# A aproximação é registrada no documento como uma propriedade nomeada,
# de modo que a justificativa original da PoC não se perde.
JUSTIFICATION_MAP = {
    "code_not_present": "code_not_present",
    "code_not_reachable": "code_not_reachable",
    "protected_by_mitigating_control": "protected_by_mitigating_control",
    "attacker_controlled_input_not_present": "requires_environment",
}


# Define a função que converte um valor em texto para uma propriedade.
def as_property(name, value):
    """
    Monta uma propriedade do CycloneDX.

    O campo value da especificação aceita apenas texto, por isso valores
    lógicos e numéricos são convertidos antes de serem gravados.
    """

    # Converte valores lógicos para texto em letras minúsculas,
    # seguindo a convenção usada em JSON.
    if isinstance(value, bool):
        value = "true" if value else "false"

    # Retorna a propriedade no formato esperado pela especificação.
    return {"name": name, "value": str(value)}


# Define a função que monta a lista de propriedades de uma
# vulnerabilidade.
def build_properties(result):
    """
    Registra as evidências da análise como propriedades nomeadas.

    A especificação do CycloneDX não possui campos para caminho de
    chamadas, ponto de entrada ou arquivos de declaração. O mecanismo
    previsto para dados adicionais é a lista properties, em que cada
    item possui um nome e um valor em texto.

    Os nomes usam o prefixo "vector:" para deixar claro que são
    específicos desta ferramenta e não fazem parte da especificação.
    """

    # Obtém as evidências registradas pela análise.
    evidence = result["evidence"]

    # Inicializa a lista de propriedades com os dados sempre presentes.
    properties = [
        as_property("vector:language", evidence["language"]),
        as_property(
            "vector:entry_points",
            ", ".join(evidence["entry_points"]),
        ),
        as_property(
            "vector:vulnerable_function",
            evidence["vulnerable_function"],
        ),
        as_property("vector:reachable", evidence["reachable"]),
        as_property(
            "vector:function_present",
            evidence["function_present"],
        ),
        as_property("vector:residual_risk", result["residual_risk"]),
        as_property(
            "vector:analysis_complete",
            evidence["analysis_complete"],
        ),
    ]

    # Verifica se a análise deixou chamadas sem resolver.
    if evidence["unresolved_calls"]:

        # Registra quantas funções contêm trechos não compreendidos.
        #
        # A informação importa para quem consome o documento: ela diz
        # que a conclusão sobre alcançabilidade tem cobertura parcial.
        properties.append(
            as_property(
                "vector:unresolved_calls",
                "; ".join(
                    f"{item['function']}: {len(item['details'])}"
                    for item in evidence["unresolved_calls"]
                ),
            )
        )

    # Verifica se existe um caminho de alcançabilidade.
    if evidence["call_path"]:

        # Registra o caminho no mesmo formato exibido ao analista.
        properties.append(
            as_property(
                "vector:call_path",
                " -> ".join(evidence["call_path"]),
            )
        )

    # Verifica se a função foi localizada em algum arquivo.
    if evidence["declared_in"]:

        # Registra os arquivos que declaram a função vulnerável.
        properties.append(
            as_property(
                "vector:declared_in",
                ", ".join(evidence["declared_in"]),
            )
        )

    # Obtém a justificativa atribuída pela PoC.
    justification = result["justification"]

    # Verifica se a justificativa precisou ser aproximada.
    #
    # A comparação detecta o caso em que o valor da PoC é diferente do
    # valor gravado no documento CycloneDX.
    if (
        justification is not None
        and JUSTIFICATION_MAP.get(justification) != justification
    ):

        # Registra a justificativa original, preservando a informação
        # que a aproximação perderia.
        properties.append(
            as_property(
                "vector:original_justification",
                justification,
            )
        )

    # Retorna a lista construída.
    return properties


# Define a função que monta o texto explicativo da análise.
def build_detail(result):
    """
    Monta o conteúdo do campo analysis.detail.

    O campo é de texto livre e reúne a conclusão da PoC, o caminho
    encontrado e as observações do analista, de modo que a decisão
    permaneça legível mesmo em ferramentas que ignorem as propriedades.
    """

    # Obtém as evidências registradas pela análise.
    evidence = result["evidence"]

    # Inicializa a lista de trechos do texto com a conclusão.
    parts = [result["detail"]]

    # Verifica se existe um caminho de alcançabilidade.
    if evidence["call_path"]:

        # Acrescenta o caminho encontrado.
        parts.append(
            f"Caminho de chamadas: "
            f"{' -> '.join(evidence['call_path'])}."
        )

    # Obtém a avaliação manual, quando realizada.
    assessment = evidence["manual_assessment"]

    # Verifica se o analista registrou alguma informação.
    if assessment:

        # Obtém a descrição da mitigação informada.
        mitigation = assessment.get("mitigation_description")

        # Verifica se existe descrição de mitigação.
        if mitigation:

            # Acrescenta a mitigação ao texto.
            parts.append(f"Mitigação: {mitigation}.")

        # Obtém as observações do analista.
        notes = assessment.get("analyst_notes")

        # Verifica se existem observações.
        if notes:

            # Acrescenta as observações ao texto.
            parts.append(f"Observações do analista: {notes}")

    # Une os trechos em um único parágrafo.
    return " ".join(parts)


# Define a função que monta o documento CycloneDX.
def create_cyclonedx_document(
    product_name,
    product_version,
    analysis_results,
    tool_version,
):
    """
    Produz um documento CycloneDX 1.6 contendo as declarações VEX.

    O documento é validável pelo schema oficial da especificação.
    """

    # Obtém a data e a hora atuais utilizando o fuso UTC.
    timestamp = datetime.now(timezone.utc).isoformat()

    # Define a referência interna do produto analisado.
    #
    # Toda vulnerabilidade precisa apontar para um componente por meio
    # do campo affects[].ref. Essa referência é o identificador usado
    # nessa ligação.
    product_ref = f"product-{product_name}@{product_version}"

    # Inicializa a lista de componentes do documento.
    components = []

    # Inicializa o dicionário que evita declarar o mesmo componente
    # mais de uma vez.
    component_refs = {}

    # Percorre os resultados para declarar os componentes afetados.
    for result in analysis_results:

        # Obtém o nome do componente associado à vulnerabilidade.
        name = result.get("component")

        # Verifica se o componente foi informado no arquivo de CVEs.
        #
        # Os campos component e component_version são opcionais. Quando
        # ausentes, a vulnerabilidade é associada ao próprio produto.
        if not name:
            continue

        # Obtém a versão do componente.
        version = result.get("component_version") or ""

        # Monta a referência interna do componente.
        ref = f"component-{name}@{version}" if version else f"component-{name}"

        # Verifica se o componente ainda não foi declarado.
        if ref not in component_refs:

            # Monta a declaração do componente.
            #
            # O tipo "library" é usado porque a PoC avalia dependências
            # de terceiros associadas a CVEs.
            component = {
                "bom-ref": ref,
                "type": "library",
                "name": name,
            }

            # Acrescenta a versão quando ela foi informada.
            if version:
                component["version"] = version

            # Declara o componente no documento.
            components.append(component)

            # Registra a referência para reutilização.
            component_refs[ref] = True

        # Armazena a referência no próprio resultado, para uso adiante.
        result["_cyclonedx_ref"] = ref

    # Inicializa a lista de vulnerabilidades do documento.
    vulnerabilities = []

    # Percorre os resultados da análise.
    for result in analysis_results:

        # Obtém o estado da análise, já compatível com a especificação.
        state = result["analysis_state"]

        # Monta o bloco de análise da vulnerabilidade.
        analysis = {
            "state": state,
            "detail": build_detail(result),
        }

        # Obtém a justificativa atribuída pela PoC.
        justification = result["justification"]

        # Verifica se existe justificativa a converter.
        if justification is not None:

            # Converte a justificativa para um valor aceito pela
            # especificação.
            converted = JUSTIFICATION_MAP.get(justification)

            # Registra a justificativa apenas quando há correspondência.
            #
            # Um valor desconhecido é omitido em vez de gravado, pois
            # invalidaria o documento perante o schema.
            if converted is not None:
                analysis["justification"] = converted

        # Verifica se existe alguma resposta recomendada.
        if result["response"]:

            # Registra as respostas recomendadas.
            analysis["response"] = result["response"]

        # Determina o componente afetado pela vulnerabilidade.
        #
        # Quando o arquivo de CVEs não informou um componente, a
        # vulnerabilidade é associada ao produto analisado.
        affected_ref = result.get("_cyclonedx_ref", product_ref)

        # Monta a vulnerabilidade no formato da especificação.
        vulnerabilities.append(
            {
                "bom-ref": f"vuln-{result['id']}",
                "id": result["id"],
                "analysis": analysis,
                "affects": [{"ref": affected_ref}],
                "properties": build_properties(result),
            }
        )

    # Remove a chave auxiliar acrescentada aos resultados.
    #
    # A limpeza evita que o campo interno apareça no documento do
    # formato próprio da PoC, que compartilha a mesma lista.
    for result in analysis_results:
        result.pop("_cyclonedx_ref", None)

    # Retorna o documento completo.
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Vector — Reachability Analysis PoC",
                        "version": tool_version,
                    }
                ]
            },
            "component": {
                "bom-ref": product_ref,
                "type": "application",
                "name": product_name,
                "version": product_version,
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


# Define a função que grava o documento CycloneDX.
def save_cyclonedx(document, output_path):

    # Converte o caminho de saída em um objeto Path.
    output_path = Path(output_path)

    # Inicia o tratamento dos erros de escrita.
    try:

        # Cria os diretórios necessários caso ainda não existam.
        if output_path.parent != Path(""):
            output_path.parent.mkdir(parents=True, exist_ok=True)

        # Abre o arquivo de saída no modo de escrita.
        with output_path.open("w", encoding="utf-8") as file:

            # Converte o objeto Python para JSON.
            json.dump(document, file, indent=2, ensure_ascii=False)

    # Captura falhas de permissão e demais erros do sistema de arquivos.
    except OSError as error:

        # Interrompe a execução informando o motivo.
        raise SourceError(
            f"Não foi possível gravar {output_path}: {error}"
        ) from error


# Define a função que deriva o nome do arquivo CycloneDX.
def derive_output_path(output_path):
    """
    Monta o caminho do arquivo CycloneDX a partir do caminho informado.

    A função é utilizada quando o analista escolhe gerar os dois
    formatos. O sufixo ".cdx" é inserido antes da extensão, seguindo a
    convenção adotada pelas ferramentas do próprio CycloneDX.

    Exemplo:

        results/vex.json  ->  results/vex.cdx.json
    """

    # Converte o caminho em um objeto Path.
    output_path = Path(output_path)

    # Monta o novo nome preservando a extensão original.
    return output_path.with_name(
        f"{output_path.stem}.cdx{output_path.suffix}"
    )
