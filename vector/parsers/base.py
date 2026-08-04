# Define a estrutura de dados compartilhada pelos analisadores.
#
# Tanto o analisador de Python quanto o de C produzem o mesmo tipo de
# resultado. Isso permite que o restante da PoC (alcançabilidade,
# classificação VEX, imagem do grafo e interface gráfica) funcione sem
# saber qual linguagem foi analisada.

# Importa dataclass para descrever a estrutura de forma declarativa.
from dataclasses import dataclass, field

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path


# Define a estrutura que representa o resultado de uma análise estática.
@dataclass
class CallGraphResult:
    """
    Resultado da análise estática de um ou mais arquivos.

    Campos:
    - language: linguagem analisada ("python" ou "c");
    - sources: arquivos efetivamente analisados;
    - graph: grafo de chamadas, no formato função -> funções chamadas;
    - declarations: função -> arquivos em que ela foi declarada;
    - failures: arquivos que não puderam ser analisados.

    O campo failures existe porque a PoC passou a aceitar pastas
    inteiras. Um único arquivo com erro de sintaxe não deve interromper
    a análise dos demais, mas o problema precisa ser registrado para que
    o analista saiba que a cobertura foi parcial.
    """

    # Armazena a linguagem analisada.
    language: str = "python"

    # Armazena a lista de arquivos analisados com sucesso.
    sources: list = field(default_factory=list)

    # Armazena o grafo de chamadas.
    #
    # Exemplo:
    #
    # {
    #     "main": ["process_request"],
    #     "process_request": ["vulnerable_function"],
    #     "vulnerable_function": []
    # }
    graph: dict = field(default_factory=dict)

    # Armazena onde cada função foi declarada.
    #
    # Exemplo:
    #
    # {
    #     "main": ["src/app.c"],
    #     "helper": ["src/util.c", "src/legacy.c"]
    # }
    #
    # Quando uma função aparece em mais de um arquivo, existe ambiguidade:
    # a PoC não diferencia funções homônimas declaradas em módulos
    # diferentes. O registro permite alertar o analista sobre isso.
    declarations: dict = field(default_factory=dict)

    # Armazena os arquivos que falharam, junto do motivo.
    #
    # Exemplo:
    #
    # [{"source": "src/quebrado.py", "error": "unexpected indent"}]
    failures: list = field(default_factory=list)

    # Armazena as chamadas que não puderam ser resolvidas.
    #
    # A chave é a função que contém a chamada, e o valor é a lista de
    # descrições dos trechos não compreendidos.
    #
    # Exemplo:
    #
    # {"main": ["chamada por expressão em obter_callback()()"]}
    #
    # Este registro é o que sustenta a superaproximação: quando existe
    # uma chamada não resolvida no caminho explorado, a ausência de um
    # caminho até a função vulnerável deixa de ser conclusiva, porque a
    # análise não compreendeu tudo o que o programa faz.
    unresolved: dict = field(default_factory=dict)

    # Armazena as funções que possuem decorador.
    #
    # Uma função decorada é registrada por um framework e chamada por
    # ele, e não pelo código analisado. Por isso ela é tratada como um
    # ponto de entrada adicional.
    decorated: list = field(default_factory=list)

    # Armazena as arestas obtidas por referência, e não por chamada
    # direta.
    #
    # Exemplo: uma função passada como argumento ou guardada em um
    # dicionário. A relação é registrada porque a função pode ser
    # chamada depois, mas o momento da chamada não é conhecido.
    #
    # Cada item é uma tupla (chamador, chamada).
    references: list = field(default_factory=list)

    # Define uma propriedade que retorna as funções declaradas,
    # em ordem alfabética.
    @property
    def functions(self):

        # Retorna os nomes das funções declaradas no código analisado.
        #
        # Observação: o grafo também contém funções apenas chamadas,
        # como printf() ou input(), que não são declaradas nos arquivos
        # analisados. Essas funções não aparecem aqui.
        return sorted(self.declarations)

    # Define uma propriedade que retorna as funções declaradas
    # em mais de um arquivo.
    @property
    def ambiguous_functions(self):

        # Retorna apenas os nomes associados a dois ou mais arquivos.
        return sorted(
            name
            for name, files in self.declarations.items()
            if len(files) > 1
        )

    # Define o método que registra a declaração de uma função.
    def add_declaration(self, function_name, source_path):

        # Garante que a função exista no grafo, mesmo que ela não
        # chame nenhuma outra função.
        self.graph.setdefault(function_name, [])

        # Obtém a lista de arquivos em que a função já foi vista.
        files = self.declarations.setdefault(function_name, [])

        # Converte o caminho para texto, mantendo o formato do
        # sistema operacional em uso.
        source_text = str(source_path)

        # Evita registrar o mesmo arquivo duas vezes.
        if source_text not in files:
            files.append(source_text)

    # Define o método que registra uma chamada entre duas funções.
    def add_call(self, caller, callee):

        # Garante que a função chamadora exista no grafo.
        callees = self.graph.setdefault(caller, [])

        # Evita registrar a mesma chamada mais de uma vez.
        if callee not in callees:
            callees.append(callee)

        # Garante que a função chamada também exista no grafo.
        #
        # Isso permite visualizar funções externas, como printf(),
        # que são chamadas mas não declaradas no código analisado.
        self.graph.setdefault(callee, [])

    # Define o método que registra uma referência a uma função.
    def add_reference(self, caller, callee):
        """
        Registra que uma função foi referenciada dentro de outra.

        A referência ocorre quando o nome de uma função aparece sem
        parênteses, como em register(tratador) ou {"run": tratador}. O
        programa guardou a função para chamá-la em outro momento.

        A aresta é criada porque, do ponto de vista da alcançabilidade,
        referenciar uma função é evidência suficiente de que ela pode
        ser executada. Trata-se de uma superaproximação deliberada: é
        preferível investigar um caminho que talvez não ocorra a deixar
        de apontar um que ocorre.
        """

        # Registra a relação no grafo, como qualquer outra chamada.
        self.add_call(caller, callee)

        # Guarda a origem da aresta, permitindo distingui-la de uma
        # chamada direta na exibição do resultado.
        if (caller, callee) not in self.references:
            self.references.append((caller, callee))

    # Define o método que registra uma chamada não compreendida.
    def add_unresolved(self, caller, description):
        """
        Registra que uma chamada não pôde ser associada a uma função.
        """

        # Obtém a lista de trechos já registrados para essa função.
        entries = self.unresolved.setdefault(caller, [])

        # Evita registrar a mesma descrição mais de uma vez.
        if description not in entries:
            entries.append(description)

    # Define o método que registra uma função decorada.
    def mark_decorated(self, function_name):
        """
        Registra que uma função possui decorador.
        """

        # Evita registrar a mesma função mais de uma vez.
        if function_name not in self.decorated:
            self.decorated.append(function_name)

    # Define o método que registra a falha de um arquivo.
    def add_failure(self, source_path, message):

        # Adiciona o arquivo e o motivo da falha à lista.
        self.failures.append(
            {
                "source": str(source_path),
                "error": message,
            }
        )


# Define a função que localiza os arquivos a serem analisados.
def collect_source_files(path, extensions):
    """
    Retorna a lista de arquivos que devem ser analisados.

    O caminho informado pode ser:
    - um arquivo, que é analisado individualmente;
    - uma pasta, percorrida recursivamente em busca das extensões
      informadas.

    Pastas de ambiente virtual, cache e controle de versão são ignoradas
    porque contêm código de terceiros que não faz parte da aplicação
    avaliada e distorceria o grafo de chamadas.
    """

    # Converte o caminho recebido em um objeto Path.
    path = Path(path)

    # Verifica se o caminho aponta para um arquivo.
    if path.is_file():

        # Retorna uma lista contendo apenas esse arquivo.
        return [path]

    # Define os nomes de pasta que devem ser ignorados durante a busca.
    ignored_directories = {
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".git",
        "node_modules",
        "build",
        "dist",
    }

    # Inicializa a lista de arquivos encontrados.
    found_files = []

    # Percorre recursivamente todo o conteúdo da pasta.
    for candidate in sorted(path.rglob("*")):

        # Ignora tudo que não for arquivo.
        if not candidate.is_file():
            continue

        # Ignora arquivos cuja extensão não interessa à análise.
        #
        # A comparação usa letras minúsculas para aceitar,
        # por exemplo, ".C" e ".PY".
        if candidate.suffix.lower() not in extensions:
            continue

        # Ignora arquivos localizados dentro das pastas excluídas.
        #
        # A verificação usa as pastas do caminho relativo, de modo que
        # uma pasta chamada "build" em qualquer nível seja descartada.
        if ignored_directories.intersection(candidate.parts):
            continue

        # Adiciona o arquivo à lista de resultados.
        found_files.append(candidate)

    # Retorna os arquivos encontrados.
    return found_files


# Define a função que lê um arquivo de código-fonte como texto.
def read_source_text(source_path):
    """
    Lê o conteúdo de um arquivo de código-fonte.

    A leitura utiliza UTF-8 e substitui os caracteres inválidos em vez de
    interromper a execução. Arquivos de código legado frequentemente
    utilizam outras codificações, como Latin-1, e a substituição evita
    que um único caractere impeça toda a análise.
    """

    # Abre o arquivo em modo texto, tolerando caracteres inválidos.
    return Path(source_path).read_text(
        encoding="utf-8",
        errors="replace",
    )
