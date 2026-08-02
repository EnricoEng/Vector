# Concentra o fluxo completo da análise.
#
# Este módulo une as etapas implementadas nos demais arquivos:
#
# 1. análise estática do código-fonte;
# 2. validação do ponto de entrada;
# 3. leitura do arquivo de CVEs;
# 4. análise de alcançabilidade;
# 5. avaliação manual de explorabilidade;
# 6. classificação e geração da declaração VEX.
#
# A linha de comando e a interface gráfica chamam a mesma função daqui.
# Isso garante que as duas produzam exatamente o mesmo resultado e evita
# duplicar a lógica da PoC em dois lugares.

# Importa a exportação no formato CycloneDX.
from .cyclonedx import (
    create_cyclonedx_document,
    derive_output_path,
    save_cyclonedx,
)

# Importa a geração da imagem do grafo.
from .graph_image import generate_call_graph_image

# Importa o seletor de analisador por linguagem.
from .parsers import analyze as analyze_source

# Importa a análise de alcançabilidade e a validação do ponto de entrada.
from .reachability import find_reachability_path, validate_entry_point

# Importa a classificação e a montagem da declaração VEX.
from .vex import (
    classify_vulnerability,
    create_vex_document,
    load_cve_file,
    save_json,
)

# Importa a versão da PoC, registrada no documento CycloneDX.
from .version import __version__


# Define os formatos de saída aceitos pela PoC.
#
# Cada entrada associa o identificador usado na linha de comando ao
# rótulo exibido na interface gráfica.
OUTPUT_FORMATS = {
    "poc": "Formato próprio da PoC",
    "cyclonedx": "CycloneDX 1.6 VEX",
    "ambos": "Os dois formatos",
}


# Define a função que executa a análise completa.
def run_analysis(
    source,
    cve_file,
    entry_point,
    product_name,
    product_version,
    language=None,
    graphs_directory="results/graphs",
    assessment_callback=None,
    progress_callback=None,
):
    """
    Executa a análise completa e devolve o resultado.

    Parâmetros:
    - source: arquivo ou pasta com o código-fonte;
    - cve_file: arquivo JSON que mapeia CVE para função;
    - entry_point: função usada como ponto de entrada;
    - product_name / product_version: identificação do produto;
    - language: "python", "c" ou None para detectar automaticamente;
    - graphs_directory: pasta que receberá os grafos;
    - assessment_callback: função chamada para coletar a avaliação
      manual de explorabilidade, ou None para não realizá-la;
    - progress_callback: função chamada com mensagens de andamento.

    O parâmetro assessment_callback recebe o identificador da CVE, o
    nome da função vulnerável e o caminho encontrado, e deve devolver um
    dicionário com as chaves attacker_input, mitigation_present,
    mitigation_description e analyst_notes, ou None.

    Esse desenho permite que o terminal colete as respostas com input()
    e que a interface gráfica as colete com caixas de diálogo, sem que
    este módulo precise saber qual das duas está em uso.

    Retorna um dicionário com:
    - vex_document: a declaração VEX simplificada;
    - static_analysis: o CallGraphResult produzido;
    - results: a lista de resultados por vulnerabilidade;
    - warnings: avisos acumulados durante a execução.
    """

    # Define uma função interna para registrar o andamento.
    def report(message):

        # Verifica se o chamador forneceu uma função de progresso.
        if progress_callback is not None:

            # Encaminha a mensagem ao chamador.
            progress_callback(message)

    # Inicializa a lista de avisos acumulados.
    warnings = []

    # Informa o início da análise estática.
    report(f"Analisando o código-fonte em: {source}")

    # Executa a análise estática do código-fonte.
    #
    # Esta chamada pode levantar SourceError, LanguageError, ParseError
    # ou DependencyError, que são tratadas pelo chamador.
    static_analysis = analyze_source(source, language)

    # Informa quantos arquivos foram analisados.
    report(
        f"Arquivos analisados: {len(static_analysis.sources)} "
        f"({static_analysis.language})"
    )

    # Obtém o grafo de chamadas.
    graph = static_analysis.graph

    # Percorre os arquivos que falharam ou foram lidos em parte.
    for failure in static_analysis.failures:

        # Monta a mensagem do aviso.
        message = f"{failure['source']}: {failure['error']}"

        # Registra o aviso na lista.
        warnings.append(message)

        # Informa o aviso ao chamador.
        report(f"Aviso: {message}")

    # Verifica se alguma função foi declarada em mais de um arquivo.
    if static_analysis.ambiguous_functions:

        # Limita a lista para não produzir uma mensagem longa demais.
        preview = ", ".join(static_analysis.ambiguous_functions[:10])

        # Monta a mensagem do aviso.
        #
        # A ambiguidade importa porque a PoC identifica funções apenas
        # pelo nome. Duas funções homônimas em arquivos diferentes são
        # tratadas como uma só, o que pode criar um caminho de
        # alcançabilidade que não existe no programa real.
        message = (
            f"Funções declaradas em mais de um arquivo foram tratadas "
            f"como uma só: {preview}. O caminho encontrado pode não "
            f"existir no programa real."
        )

        # Registra o aviso na lista.
        warnings.append(message)

        # Informa o aviso ao chamador.
        report(f"Aviso: {message}")

    # Valida o ponto de entrada informado.
    #
    # A validação ocorre antes da leitura das CVEs para que o analista
    # receba o erro mais provável primeiro.
    validate_entry_point(static_analysis, entry_point)

    # Carrega e valida o arquivo JSON contendo as CVEs.
    vulnerabilities = load_cve_file(cve_file)

    # Inicializa a lista de resultados.
    analysis_results = []

    # Percorre as vulnerabilidades presentes no arquivo JSON.
    for cve_entry in vulnerabilities:

        # Obtém o identificador da CVE.
        cve_id = cve_entry["id"]

        # Obtém o nome da função vulnerável.
        vulnerable_function = cve_entry["function"]

        # Informa qual vulnerabilidade está sendo avaliada.
        report(f"Avaliando {cve_id} ({vulnerable_function})")

        # Procura um caminho entre o ponto de entrada
        # e a função vulnerável.
        path = find_reachability_path(
            graph,
            entry_point,
            vulnerable_function,
        )

        # Define a alcançabilidade com base na existência do caminho.
        is_reachable = path is not None

        # Verifica se a função vulnerável existe no código analisado.
        function_present = vulnerable_function in graph

        # Verifica se a função sequer aparece no código.
        if not function_present:

            # Monta a mensagem do aviso.
            #
            # Este caso merece destaque: a conclusão "não alcançável"
            # pode significar que a função não é chamada, mas também
            # que o arquivo que a contém não foi incluído na análise.
            message = (
                f"{cve_id}: a função '{vulnerable_function}' não foi "
                f"encontrada no código analisado. Verifique se o "
                f"escopo da análise inclui o arquivo que a declara."
            )

            # Registra o aviso na lista.
            warnings.append(message)

            # Informa o aviso ao chamador.
            report(f"Aviso: {message}")

        # Gera a representação visual do grafo.
        graph_files = generate_call_graph_image(
            graph=graph,
            entry_point=entry_point,
            vulnerable_function=vulnerable_function,
            reachability_path=path,
            cve_id=cve_id,
            output_directory=graphs_directory,
        )

        # Verifica se a geração produziu algum aviso.
        if graph_files["warning"]:

            # Registra o aviso na lista, evitando repetir a mesma
            # mensagem para cada vulnerabilidade analisada.
            if graph_files["warning"] not in warnings:
                warnings.append(graph_files["warning"])

                # Informa o aviso ao chamador.
                report(f"Aviso: {graph_files['warning']}")

        # Inicializa a avaliação manual como ausente.
        assessment = None

        # Executa o questionário somente se:
        #
        # - a função for alcançável;
        # - o chamador tiver fornecido uma forma de coletar respostas.
        if is_reachable and assessment_callback is not None:

            # Coleta os dois fatores manuais:
            #
            # 1. controle da entrada;
            # 2. existência de mitigação.
            assessment = assessment_callback(
                cve_id,
                vulnerable_function,
                path,
            )

        # Classifica a vulnerabilidade.
        classification = classify_vulnerability(is_reachable, assessment)

        # Cria o registro das evidências utilizadas.
        evidence = {
            "analysis_type": "static_call_graph",
            "language": static_analysis.language,
            "entry_point": entry_point,
            "vulnerable_function": vulnerable_function,
            "function_present": function_present,
            "declared_in": static_analysis.declarations.get(
                vulnerable_function,
                [],
            ),
            "reachable": is_reachable,
            "call_path": path,
            "manual_assessment": assessment,
            "call_graph_dot": graph_files["dot_file"],
            "call_graph_image": graph_files["image_file"],
        }

        # Cria o resultado da vulnerabilidade.
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

        # Adiciona o resultado à lista.
        analysis_results.append(result)

    # Cria a declaração VEX simplificada.
    vex_document = create_vex_document(
        product_name=product_name,
        product_version=product_version,
        source_file=str(source),
        entry_point=entry_point,
        analysis_results=analysis_results,
        language=static_analysis.language,
        analyzed_files=static_analysis.sources,
        analysis_warnings=warnings,
    )

    # Retorna o resultado completo da análise.
    return {
        "vex_document": vex_document,
        "static_analysis": static_analysis,
        "results": analysis_results,
        "warnings": warnings,
    }


# Define a função que grava a saída nos formatos escolhidos.
def save_analysis(analysis, output_path, output_format="poc"):
    """
    Grava o resultado da análise nos formatos solicitados.

    Parâmetros:
    - analysis: o dicionário devolvido por run_analysis;
    - output_path: caminho do arquivo de saída;
    - output_format: "poc", "cyclonedx" ou "ambos".

    Quando os dois formatos são solicitados, o arquivo da PoC recebe o
    caminho informado e o documento CycloneDX recebe o mesmo caminho com
    o sufixo ".cdx" antes da extensão. Isso evita que um formato
    sobrescreva o outro.

    Devolve a lista de arquivos gravados, na ordem em que foram criados.

    A linha de comando e a interface gráfica usam esta função, de modo
    que a escolha do formato se comporte da mesma forma nas duas.
    """

    # Verifica se o formato solicitado é conhecido.
    if output_format not in OUTPUT_FORMATS:

        # Monta a lista de formatos válidos para a mensagem de erro.
        valid = ", ".join(sorted(OUTPUT_FORMATS))

        # Interrompe a execução informando as opções válidas.
        raise ValueError(
            f"Formato de saída não suportado: '{output_format}'. "
            f"Use um destes: {valid}."
        )

    # Inicializa a lista de arquivos gravados.
    written_files = []

    # Verifica se o formato próprio da PoC deve ser gerado.
    if output_format in ("poc", "ambos"):

        # Grava a declaração no formato próprio.
        save_json(analysis["vex_document"], output_path)

        # Registra o arquivo gravado.
        written_files.append(str(output_path))

    # Verifica se o documento CycloneDX deve ser gerado.
    if output_format in ("cyclonedx", "ambos"):

        # Obtém os dados do produto a partir da declaração já montada,
        # evitando repetir os parâmetros da análise.
        product = analysis["vex_document"]["product"]

        # Monta o documento CycloneDX.
        document = create_cyclonedx_document(
            product_name=product["name"],
            product_version=product["version"],
            analysis_results=analysis["results"],
            tool_version=__version__,
        )

        # Define o caminho do arquivo CycloneDX.
        #
        # Quando apenas o CycloneDX é solicitado, ele recebe o caminho
        # informado pelo analista. Quando os dois formatos são gerados,
        # o sufixo evita a sobrescrita.
        if output_format == "ambos":
            cyclonedx_path = derive_output_path(output_path)
        else:
            cyclonedx_path = output_path

        # Grava o documento CycloneDX.
        save_cyclonedx(document, cyclonedx_path)

        # Registra o arquivo gravado.
        written_files.append(str(cyclonedx_path))

    # Retorna os arquivos gravados.
    return written_files
