# Implementa a interface gráfica da PoC.
#
# A interface é escrita com tkinter, que faz parte da biblioteca padrão
# do Python. Essa escolha evita acrescentar uma dependência apenas para
# desenhar a janela e mantém a PoC executável em qualquer instalação
# padrão do Python.
#
# A interface não contém regra de análise. Ela apenas coleta os dados
# informados pelo analista e chama vector.analysis.run_analysis, a mesma
# função usada pela linha de comando.

# Importa o módulo sys, utilizado para escrever avisos no terminal e
# para identificar o sistema operacional em uso.
import sys

# Importa o tkinter, base da interface gráfica.
import tkinter as tk

# Importa os diálogos de arquivo e as caixas de mensagem.
from tkinter import filedialog, messagebox

# Importa os widgets com aparência nativa do sistema operacional.
from tkinter import ttk

# Importa o widget de texto com barra de rolagem.
from tkinter.scrolledtext import ScrolledText

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path

# Importa as funções que executam e gravam a análise completa.
from .analysis import OUTPUT_FORMATS, run_analysis, save_analysis

# Importa a exceção base, usada para tratar todos os erros previstos.
from .errors import VectorError

# Importa os analisadores, usados para descobrir as funções declaradas
# antes de executar a análise completa.
from .parsers import SUPPORTED_LANGUAGES, analyze as analyze_source

# Importa a sugestão de pontos de entrada.
from .reachability import suggest_entry_points


# Define o texto usado na opção de detecção automática da linguagem.
AUTO_DETECT_LABEL = "Detectar automaticamente"


# Define a versão mínima do Tk capaz de desenhar a interface.
#
# O macOS inclui o Tcl/Tk 8.5.9, uma versão congelada por volta de 2010
# e depreciada pela Apple desde o macOS 10.14. Nas versões recentes do
# sistema, essa build abre a janela mas não desenha os widgets,
# produzindo uma tela inteiramente branca.
#
# O problema está no Tk distribuído com o sistema, não na PoC.
MINIMUM_TK_VERSION = 8.6


# Define a função que verifica a versão do Tk instalada.
def check_tk_version():
    """
    Verifica se o Tk instalado consegue desenhar a interface.

    Devolve None quando a versão é adequada, ou uma mensagem explicando
    o problema e como corrigi-lo.

    A verificação existe porque o sintoma da versão antiga é uma janela
    em branco, sem qualquer mensagem de erro. Sem este aviso, não há
    como o analista descobrir a causa.
    """

    # Verifica se a versão do Tk é suficiente.
    if tk.TkVersion >= MINIMUM_TK_VERSION:

        # Devolve None, indicando que está tudo certo.
        return None

    # Devolve a mensagem explicando o problema e a correção.
    return (
        f"Aviso: o Tk instalado é a versão {tk.TkVersion}, anterior à "
        f"{MINIMUM_TK_VERSION}.\n\n"
        f"No macOS, o Python distribuído com as Command Line Tools "
        f"utiliza o Tcl/Tk 8.5.9, depreciado pela Apple. Nas versões "
        f"recentes do sistema, essa build abre a janela mas não "
        f"desenha os campos, resultando em uma tela em branco.\n\n"
        f"Para corrigir, instale o Python a partir de "
        f"https://www.python.org/downloads/macos/, que acompanha o "
        f"Tk 8.6, e execute a PoC com esse interpretador.\n\n"
        f"A análise pela linha de comando não é afetada e continua "
        f"funcionando normalmente:\n"
        f"    python3 analyzer.py --source ... --cves ...\n"
    )


# Define a janela que coleta a avaliação manual de explorabilidade.
class ManualAssessmentDialog(tk.Toplevel):
    """
    Caixa de diálogo com as perguntas da avaliação manual.

    As perguntas são as mesmas feitas pelo terminal:

    1. O atacante controla a entrada?
    2. Existe uma mitigação?

    A pergunta sobre alcançabilidade não é feita porque esse resultado
    já foi obtido automaticamente pelo algoritmo de reachability.
    """

    # O método __init__ é executado quando a janela é criada.
    def __init__(self, parent, cve_id, function_name, path):

        # Chama o construtor da classe Toplevel.
        super().__init__(parent)

        # Define o título da janela.
        self.title(f"Avaliação manual — {cve_id}")

        # Impede que a janela seja redimensionada, já que o conteúdo
        # tem tamanho fixo.
        self.resizable(False, False)

        # Inicializa o resultado como None.
        #
        # O valor permanece None caso o analista feche a janela sem
        # responder, situação em que a vulnerabilidade fica em
        # investigação.
        self.result = None

        # Cria a variável que armazena a resposta sobre a entrada.
        #
        # Os valores possíveis são "sim", "nao" e "desconhecido".
        self.attacker_input = tk.StringVar(value="desconhecido")

        # Cria a variável que armazena a resposta sobre a mitigação.
        self.mitigation_present = tk.StringVar(value="desconhecido")

        # Monta os widgets da janela.
        self.build_widgets(cve_id, function_name, path)

        # Impede a interação com a janela principal enquanto esta
        # caixa de diálogo estiver aberta.
        self.transient(parent)
        self.grab_set()

        # Trata o fechamento pelo botão da barra de título como
        # cancelamento.
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    # Define o método que monta os widgets da janela.
    def build_widgets(self, cve_id, function_name, path):

        # Cria o quadro principal com espaçamento interno.
        frame = ttk.Frame(self, padding=16)

        # Posiciona o quadro ocupando toda a janela.
        frame.pack(fill="both", expand=True)

        # Exibe o identificador da vulnerabilidade.
        ttk.Label(
            frame,
            text=f"CVE: {cve_id}",
            font=("TkDefaultFont", 11, "bold"),
        ).pack(anchor="w")

        # Exibe a função vulnerável associada.
        ttk.Label(
            frame,
            text=f"Função vulnerável: {function_name}",
        ).pack(anchor="w", pady=(4, 0))

        # Exibe o caminho encontrado pela análise de alcançabilidade.
        #
        # O caminho ajuda o analista a decidir se o atacante realmente
        # controla a entrada que chega até a função vulnerável.
        if path:
            ttk.Label(
                frame,
                text=f"Caminho: {' -> '.join(path)}",
                wraplength=460,
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        # Acrescenta uma linha separadora.
        ttk.Separator(frame).pack(fill="x", pady=12)

        # Exibe a primeira pergunta.
        ttk.Label(
            frame,
            text=(
                "O atacante controla a entrada que chega à função "
                "vulnerável?"
            ),
            wraplength=460,
            justify="left",
        ).pack(anchor="w")

        # Cria os botões de resposta da primeira pergunta.
        self.build_answer_row(frame, self.attacker_input)

        # Exibe a segunda pergunta.
        ttk.Label(
            frame,
            text="Existe mitigação que impeça a exploração?",
            wraplength=460,
            justify="left",
        ).pack(anchor="w", pady=(12, 0))

        # Cria os botões de resposta da segunda pergunta.
        self.build_answer_row(frame, self.mitigation_present)

        # Exibe o rótulo do campo de descrição da mitigação.
        ttk.Label(
            frame,
            text="Descrição da mitigação (opcional):",
        ).pack(anchor="w", pady=(12, 2))

        # Cria o campo de descrição da mitigação.
        self.mitigation_description = ttk.Entry(frame, width=60)

        # Posiciona o campo.
        self.mitigation_description.pack(fill="x")

        # Exibe o rótulo do campo de observações.
        ttk.Label(
            frame,
            text="Observações do analista:",
        ).pack(anchor="w", pady=(12, 2))

        # Cria o campo de observações, com espaço para algumas linhas.
        self.analyst_notes = tk.Text(frame, height=4, width=60)

        # Posiciona o campo.
        self.analyst_notes.pack(fill="x")

        # Cria o quadro que agrupa os botões finais.
        buttons = ttk.Frame(frame)

        # Posiciona o quadro dos botões.
        buttons.pack(fill="x", pady=(16, 0))

        # Cria o botão que confirma as respostas.
        ttk.Button(
            buttons,
            text="Confirmar",
            command=self.on_confirm,
        ).pack(side="right")

        # Cria o botão que cancela a avaliação manual.
        ttk.Button(
            buttons,
            text="Não sei responder",
            command=self.on_cancel,
        ).pack(side="right", padx=(0, 8))

    # Define o método que cria uma linha de botões de resposta.
    def build_answer_row(self, parent, variable):

        # Cria o quadro que agrupa as três opções.
        row = ttk.Frame(parent)

        # Posiciona o quadro.
        row.pack(anchor="w", pady=(4, 0))

        # Percorre as três respostas possíveis.
        #
        # Cada item associa o texto exibido ao valor armazenado.
        for label, value in (
            ("Sim", "sim"),
            ("Não", "nao"),
            ("Desconhecido", "desconhecido"),
        ):

            # Cria o botão de opção correspondente.
            ttk.Radiobutton(
                row,
                text=label,
                value=value,
                variable=variable,
            ).pack(side="left", padx=(0, 12))

    # Define o método que converte a resposta em um valor lógico.
    @staticmethod
    def to_boolean(value):
        """
        Converte a resposta escolhida em True, False ou None.

        O valor None representa "desconhecido" e leva a vulnerabilidade
        ao estado UNDER_INVESTIGATION.
        """

        # Verifica se a resposta foi afirmativa.
        if value == "sim":
            return True

        # Verifica se a resposta foi negativa.
        if value == "nao":
            return False

        # Retorna None para a resposta desconhecida.
        return None

    # Define o método executado ao confirmar as respostas.
    def on_confirm(self):

        # Converte a resposta sobre o controle da entrada.
        attacker_input = self.to_boolean(self.attacker_input.get())

        # Inicializa a mitigação como desconhecida.
        mitigation_present = None

        # Inicializa a descrição da mitigação como vazia.
        mitigation_description = None

        # A resposta sobre mitigação só é considerada quando
        # o atacante controla a entrada.
        #
        # Esse é o mesmo critério aplicado no terminal, em que a
        # pergunta sequer chega a ser feita nos demais casos.
        if attacker_input is True:

            # Converte a resposta sobre a mitigação.
            mitigation_present = self.to_boolean(
                self.mitigation_present.get()
            )

            # Verifica se existe mitigação.
            if mitigation_present is True:

                # Obtém a descrição informada, sem espaços nas pontas.
                mitigation_description = (
                    self.mitigation_description.get().strip()
                )

        # Armazena o resultado da avaliação manual.
        self.result = {
            "attacker_input": attacker_input,
            "mitigation_present": mitigation_present,
            "mitigation_description": mitigation_description,
            "analyst_notes": self.analyst_notes.get(
                "1.0",
                "end",
            ).strip(),
        }

        # Fecha a janela.
        self.destroy()

    # Define o método executado ao cancelar a avaliação manual.
    def on_cancel(self):

        # Mantém o resultado como None, o que leva a vulnerabilidade
        # ao estado UNDER_INVESTIGATION.
        self.result = None

        # Fecha a janela.
        self.destroy()


# Define a janela principal da PoC.
class AnalyzerWindow(ttk.Frame):
    """
    Janela principal da interface gráfica.

    Reúne os campos necessários à análise, executa o fluxo e exibe o
    andamento e o resultado em um registro de texto.
    """

    # O método __init__ é executado quando a janela é criada.
    def __init__(self, master):

        # Chama o construtor da classe Frame, definindo o espaçamento.
        super().__init__(master, padding=12)

        # Posiciona o quadro ocupando toda a janela.
        self.pack(fill="both", expand=True)

        # Cria a variável que armazena a linguagem escolhida.
        #
        # Este é o campo pedido no requisito: o analista seleciona se o
        # código a ser analisado é .py ou .c.
        self.language = tk.StringVar(value=AUTO_DETECT_LABEL)

        # Cria a variável que armazena o caminho do código-fonte.
        self.source = tk.StringVar()

        # Cria a variável que armazena o arquivo de CVEs.
        self.cve_file = tk.StringVar()

        # Cria a variável que armazena o ponto de entrada.
        self.entry_point = tk.StringVar(value="main")

        # Cria a variável que armazena o nome do produto.
        self.product_name = tk.StringVar()

        # Cria a variável que armazena a versão do produto.
        self.product_version = tk.StringVar()

        # Cria a variável que armazena o arquivo de saída.
        self.output_file = tk.StringVar(
            value=str(Path("results") / "vex.json")
        )

        # Cria a variável que indica se a avaliação manual será feita.
        self.manual_assessment = tk.BooleanVar(value=True)

        # Cria a variável que armazena o formato da declaração gerada.
        self.output_format = tk.StringVar(value="poc")

        # Monta os widgets da janela.
        self.build_widgets()

    # Define o método que monta os widgets da janela.
    def build_widgets(self):

        # Cria o quadro do formulário.
        form = ttk.Frame(self)

        # Posiciona o formulário.
        form.pack(fill="x")

        # Faz a coluna do meio absorver o espaço disponível quando a
        # janela é redimensionada.
        form.columnconfigure(1, weight=1)

        # Inicializa o contador de linhas do formulário.
        row = 0

        # Exibe o rótulo da seleção de linguagem.
        ttk.Label(
            form,
            text="Linguagem do código-fonte:",
        ).grid(row=row, column=0, sticky="w", pady=(0, 4))

        # Cria o quadro que agrupa as opções de linguagem.
        language_row = ttk.Frame(form)

        # Posiciona o quadro das opções.
        language_row.grid(
            row=row,
            column=1,
            columnspan=2,
            sticky="w",
            pady=(0, 4),
        )

        # Cria a opção de detecção automática.
        ttk.Radiobutton(
            language_row,
            text=AUTO_DETECT_LABEL,
            value=AUTO_DETECT_LABEL,
            variable=self.language,
        ).pack(side="left", padx=(0, 12))

        # Percorre as linguagens suportadas pela PoC.
        for name, definition in SUPPORTED_LANGUAGES.items():

            # Cria o botão de opção da linguagem atual.
            #
            # Os rótulos vêm do próprio registro de linguagens, de modo
            # que incluir uma nova linguagem no analisador a faça
            # aparecer aqui automaticamente.
            ttk.Radiobutton(
                language_row,
                text=definition["label"],
                value=name,
                variable=self.language,
            ).pack(side="left", padx=(0, 12))

        # Avança para a próxima linha do formulário.
        row += 1

        # Cria a linha do código-fonte, com dois botões de seleção.
        ttk.Label(
            form,
            text="Código-fonte:",
        ).grid(row=row, column=0, sticky="w", pady=4)

        # Cria o campo que exibe o caminho escolhido.
        ttk.Entry(
            form,
            textvariable=self.source,
        ).grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 8))

        # Cria o quadro que agrupa os botões de seleção.
        source_buttons = ttk.Frame(form)

        # Posiciona o quadro dos botões.
        source_buttons.grid(row=row, column=2, sticky="w", pady=4)

        # Cria o botão que seleciona um arquivo.
        ttk.Button(
            source_buttons,
            text="Arquivo...",
            command=self.choose_source_file,
            width=10,
        ).pack(side="left")

        # Cria o botão que seleciona uma pasta.
        #
        # A seleção de pasta atende ao requisito de analisar um projeto
        # inteiro, e não apenas um arquivo isolado.
        ttk.Button(
            source_buttons,
            text="Pasta...",
            command=self.choose_source_directory,
            width=8,
        ).pack(side="left", padx=(4, 0))

        # Avança para a próxima linha do formulário.
        row += 1

        # Cria a linha do arquivo de CVEs.
        row = self.build_file_row(
            form,
            row,
            "Arquivo de CVEs (JSON):",
            self.cve_file,
            self.choose_cve_file,
            "Abrir...",
        )

        # Cria a linha do ponto de entrada.
        ttk.Label(
            form,
            text="Ponto de entrada:",
        ).grid(row=row, column=0, sticky="w", pady=4)

        # Cria a caixa de seleção editável do ponto de entrada.
        #
        # A caixa começa vazia e é preenchida pelo botão "Detectar",
        # que analisa o código e lista as funções encontradas.
        self.entry_point_box = ttk.Combobox(
            form,
            textvariable=self.entry_point,
        )

        # Posiciona a caixa de seleção.
        self.entry_point_box.grid(
            row=row,
            column=1,
            sticky="ew",
            pady=4,
            padx=(8, 8),
        )

        # Cria o botão que detecta as funções do código-fonte.
        ttk.Button(
            form,
            text="Detectar",
            command=self.detect_entry_points,
            width=10,
        ).grid(row=row, column=2, sticky="w", pady=4)

        # Avança para a próxima linha do formulário.
        row += 1

        # Cria a linha do nome do produto.
        row = self.build_text_row(
            form,
            row,
            "Nome do produto:",
            self.product_name,
        )

        # Cria a linha da versão do produto.
        row = self.build_text_row(
            form,
            row,
            "Versão do produto:",
            self.product_version,
        )

        # Cria a linha do arquivo de saída.
        row = self.build_file_row(
            form,
            row,
            "Declaração VEX (saída):",
            self.output_file,
            self.choose_output_file,
            "Salvar...",
        )

        # Exibe o rótulo da seleção de formato.
        ttk.Label(
            form,
            text="Formato da declaração:",
        ).grid(row=row, column=0, sticky="w", pady=4)

        # Cria o quadro que agrupa as opções de formato.
        format_row = ttk.Frame(form)

        # Posiciona o quadro das opções.
        format_row.grid(
            row=row,
            column=1,
            columnspan=2,
            sticky="w",
            pady=4,
        )

        # Percorre os formatos de saída suportados.
        #
        # Os rótulos vêm do próprio registro de formatos, de modo que a
        # interface acompanhe automaticamente qualquer formato novo
        # acrescentado ao motor de análise.
        for name, label in OUTPUT_FORMATS.items():

            # Cria o botão de opção do formato atual.
            ttk.Radiobutton(
                format_row,
                text=label,
                value=name,
                variable=self.output_format,
            ).pack(side="left", padx=(0, 12))

        # Avança para a próxima linha do formulário.
        row += 1

        # Cria a opção que ativa a avaliação manual.
        ttk.Checkbutton(
            form,
            text=(
                "Perguntar sobre explorabilidade quando a função for "
                "alcançável"
            ),
            variable=self.manual_assessment,
        ).grid(row=row, column=1, columnspan=2, sticky="w", pady=(8, 4))

        # Avança para a próxima linha do formulário.
        row += 1

        # Cria o quadro que agrupa os botões de ação.
        actions = ttk.Frame(self)

        # Posiciona o quadro dos botões.
        actions.pack(fill="x", pady=(12, 8))

        # Cria o botão que executa a análise.
        self.analyze_button = ttk.Button(
            actions,
            text="Analisar",
            command=self.run,
        )

        # Posiciona o botão de análise.
        self.analyze_button.pack(side="left")

        # Cria o botão que limpa o registro de execução.
        ttk.Button(
            actions,
            text="Limpar registro",
            command=self.clear_log,
        ).pack(side="left", padx=(8, 0))

        # Cria o botão que abre a pasta dos resultados.
        self.open_button = ttk.Button(
            actions,
            text="Abrir pasta dos resultados",
            command=self.open_results_directory,
            state="disabled",
        )

        # Posiciona o botão de abertura da pasta.
        self.open_button.pack(side="left", padx=(8, 0))

        # Exibe o rótulo do registro de execução.
        ttk.Label(
            self,
            text="Registro da análise:",
        ).pack(anchor="w")

        # Cria a área de texto que exibe o andamento e o resultado.
        self.log = ScrolledText(
            self,
            height=18,
            wrap="word",
            state="disabled",
        )

        # Posiciona a área de texto.
        self.log.pack(fill="both", expand=True, pady=(4, 0))

    # Define o método que cria uma linha simples de texto.
    def build_text_row(self, form, row, label, variable):

        # Exibe o rótulo da linha.
        ttk.Label(form, text=label).grid(
            row=row,
            column=0,
            sticky="w",
            pady=4,
        )

        # Cria o campo de texto associado à variável.
        ttk.Entry(form, textvariable=variable).grid(
            row=row,
            column=1,
            sticky="ew",
            pady=4,
            padx=(8, 8),
        )

        # Devolve o número da próxima linha.
        return row + 1

    # Define o método que cria uma linha com botão de seleção.
    def build_file_row(
        self,
        form,
        row,
        label,
        variable,
        command,
        button_text,
    ):

        # Exibe o rótulo da linha.
        ttk.Label(form, text=label).grid(
            row=row,
            column=0,
            sticky="w",
            pady=4,
        )

        # Cria o campo que exibe o caminho escolhido.
        ttk.Entry(form, textvariable=variable).grid(
            row=row,
            column=1,
            sticky="ew",
            pady=4,
            padx=(8, 8),
        )

        # Cria o botão que abre o diálogo de seleção.
        ttk.Button(
            form,
            text=button_text,
            command=command,
            width=10,
        ).grid(row=row, column=2, sticky="w", pady=4)

        # Devolve o número da próxima linha.
        return row + 1

    # Define o método que devolve a linguagem escolhida.
    def selected_language(self):
        """
        Devolve o identificador da linguagem, ou None para detecção
        automática.
        """

        # Obtém o valor selecionado.
        value = self.language.get()

        # Verifica se a opção é a detecção automática.
        if value == AUTO_DETECT_LABEL:

            # Devolve None, que aciona a detecção pela extensão.
            return None

        # Devolve o identificador da linguagem escolhida.
        return value

    # Define o método que monta o filtro do diálogo de arquivos.
    def source_filetypes(self):
        """
        Monta a lista de tipos de arquivo do diálogo de seleção.

        O filtro reflete a linguagem escolhida, de modo que selecionar
        "C (.c / .h)" faça o diálogo mostrar apenas arquivos em C.
        """

        # Obtém a linguagem escolhida.
        language = self.selected_language()

        # Executa quando o analista escolheu Python.
        if language == "python":
            return [
                ("Código Python", "*.py *.pyw"),
                ("Todos os arquivos", "*.*"),
            ]

        # Executa quando o analista escolheu C.
        if language == "c":
            return [
                ("Código C", "*.c *.h"),
                ("Todos os arquivos", "*.*"),
            ]

        # Executa na detecção automática, aceitando as duas linguagens.
        return [
            ("Código Python ou C", "*.py *.pyw *.c *.h"),
            ("Código Python", "*.py *.pyw"),
            ("Código C", "*.c *.h"),
            ("Todos os arquivos", "*.*"),
        ]

    # Define o método que seleciona um arquivo de código-fonte.
    def choose_source_file(self):

        # Abre o diálogo de seleção de arquivo.
        chosen = filedialog.askopenfilename(
            title="Selecione o arquivo de código-fonte",
            filetypes=self.source_filetypes(),
        )

        # Verifica se o analista escolheu um arquivo.
        if chosen:

            # Armazena o caminho escolhido.
            self.source.set(chosen)

    # Define o método que seleciona uma pasta de código-fonte.
    def choose_source_directory(self):

        # Abre o diálogo de seleção de pasta.
        chosen = filedialog.askdirectory(
            title="Selecione a pasta do projeto",
        )

        # Verifica se o analista escolheu uma pasta.
        if chosen:

            # Armazena o caminho escolhido.
            self.source.set(chosen)

    # Define o método que seleciona o arquivo de CVEs.
    def choose_cve_file(self):

        # Abre o diálogo de seleção de arquivo.
        chosen = filedialog.askopenfilename(
            title="Selecione o arquivo JSON com as CVEs",
            filetypes=[
                ("Arquivo JSON", "*.json"),
                ("Todos os arquivos", "*.*"),
            ],
        )

        # Verifica se o analista escolheu um arquivo.
        if chosen:

            # Armazena o caminho escolhido.
            self.cve_file.set(chosen)

    # Define o método que seleciona o arquivo de saída.
    def choose_output_file(self):

        # Abre o diálogo de gravação de arquivo.
        chosen = filedialog.asksaveasfilename(
            title="Salvar a declaração VEX",
            defaultextension=".json",
            filetypes=[
                ("Arquivo JSON", "*.json"),
                ("Todos os arquivos", "*.*"),
            ],
        )

        # Verifica se o analista escolheu um arquivo.
        if chosen:

            # Armazena o caminho escolhido.
            self.output_file.set(chosen)

    # Define o método que escreve uma mensagem no registro.
    def write(self, message):

        # Habilita a edição do widget, que permanece somente leitura
        # para impedir que o analista altere o registro.
        self.log.configure(state="normal")

        # Acrescenta a mensagem ao final do texto.
        self.log.insert("end", f"{message}\n")

        # Rola o texto até a última linha.
        self.log.see("end")

        # Devolve o widget ao estado somente leitura.
        self.log.configure(state="disabled")

        # Redesenha a interface imediatamente.
        #
        # A análise roda na mesma thread da interface, então esta
        # chamada é o que mantém o registro visível durante a execução.
        self.update_idletasks()

    # Define o método que limpa o registro de execução.
    def clear_log(self):

        # Habilita a edição do widget.
        self.log.configure(state="normal")

        # Remove todo o conteúdo.
        self.log.delete("1.0", "end")

        # Devolve o widget ao estado somente leitura.
        self.log.configure(state="disabled")

    # Define o método que detecta as funções do código-fonte.
    def detect_entry_points(self):
        """
        Analisa o código-fonte e preenche a lista de pontos de entrada.

        A detecção evita que o analista precise digitar o nome exato da
        função, que é a causa mais comum de erro na execução.
        """

        # Obtém o caminho do código-fonte, sem espaços nas pontas.
        source = self.source.get().strip()

        # Verifica se o caminho foi informado.
        if not source:

            # Avisa o analista e interrompe a detecção.
            messagebox.showwarning(
                "Código-fonte não informado",
                "Selecione o arquivo ou a pasta do código-fonte "
                "antes de detectar os pontos de entrada.",
            )
            return

        # Inicia o tratamento dos erros previstos pela PoC.
        try:

            # Executa apenas a análise estática do código.
            result = analyze_source(source, self.selected_language())

        # Captura os erros previstos.
        except VectorError as error:

            # Exibe a mensagem em uma caixa de erro.
            messagebox.showerror("Erro na análise", str(error))
            return

        # Obtém as funções candidatas a ponto de entrada.
        suggestions = suggest_entry_points(result)

        # Monta a lista exibida na caixa de seleção.
        #
        # As candidatas aparecem primeiro, seguidas das demais funções
        # declaradas, para que o analista possa escolher qualquer uma.
        options = suggestions + [
            name
            for name in result.functions
            if name not in suggestions
        ]

        # Preenche a caixa de seleção com as opções encontradas.
        self.entry_point_box["values"] = options

        # Informa o resultado da detecção no registro.
        self.write(
            f"Detecção concluída: {len(result.functions)} funções "
            f"declaradas em {len(result.sources)} arquivo(s) "
            f"({result.language})."
        )

        # Verifica se existe alguma sugestão e se o campo ainda contém
        # o valor padrão, que não foi escolhido pelo analista.
        if suggestions and self.entry_point.get() in ("", "main"):

            # Verifica se o valor padrão não existe no código.
            if self.entry_point.get() not in result.graph:

                # Sugere a primeira candidata encontrada.
                self.entry_point.set(suggestions[0])

                # Informa a sugestão no registro.
                self.write(
                    f"Ponto de entrada sugerido: {suggestions[0]}"
                )

    # Define o método que valida os campos do formulário.
    def validate_form(self):
        """
        Verifica se os campos obrigatórios foram preenchidos.

        Devolve None quando está tudo certo, ou a mensagem de erro.
        """

        # Percorre os campos obrigatórios e seus rótulos.
        for variable, label in (
            (self.source, "Código-fonte"),
            (self.cve_file, "Arquivo de CVEs"),
            (self.entry_point, "Ponto de entrada"),
            (self.product_name, "Nome do produto"),
            (self.product_version, "Versão do produto"),
            (self.output_file, "Declaração VEX (saída)"),
        ):

            # Verifica se o campo está vazio.
            if not variable.get().strip():

                # Devolve a mensagem indicando o campo pendente.
                return f"O campo '{label}' precisa ser preenchido."

        # Devolve None quando todos os campos estão preenchidos.
        return None

    # Define o método que coleta a avaliação manual.
    def ask_assessment(self, cve_id, function_name, path):
        """
        Abre a caixa de diálogo da avaliação manual e devolve as
        respostas do analista.

        Esta função é passada ao motor de análise como callback, no
        lugar da coleta por terminal usada pela linha de comando.
        """

        # Cria a caixa de diálogo.
        dialog = ManualAssessmentDialog(
            self.winfo_toplevel(),
            cve_id,
            function_name,
            path,
        )

        # Aguarda o fechamento da janela antes de continuar.
        self.wait_window(dialog)

        # Devolve as respostas coletadas.
        return dialog.result

    # Define o método que executa a análise.
    def run(self):

        # Valida os campos do formulário.
        error_message = self.validate_form()

        # Verifica se algum campo obrigatório está pendente.
        if error_message:

            # Exibe o aviso e interrompe a execução.
            messagebox.showwarning("Campo obrigatório", error_message)
            return

        # Desabilita o botão para impedir execuções simultâneas.
        self.analyze_button.configure(state="disabled")

        # Inicia o tratamento dos erros previstos pela PoC.
        try:

            # Limpa o registro antes de começar.
            self.clear_log()

            # Informa o início da análise.
            self.write("=" * 60)
            self.write("Iniciando a análise.")

            # Define a forma de coletar a avaliação manual.
            #
            # Quando a opção está desmarcada, o valor None indica ao
            # motor de análise que o questionário não deve ser feito.
            assessment_callback = None

            # Verifica se a avaliação manual foi solicitada.
            if self.manual_assessment.get():

                # Usa a coleta pela caixa de diálogo.
                assessment_callback = self.ask_assessment

            # Obtém a pasta de saída, usada para gravar os grafos ao
            # lado da declaração VEX.
            output_path = Path(self.output_file.get().strip())

            # Executa a análise completa.
            analysis = run_analysis(
                source=self.source.get().strip(),
                cve_file=self.cve_file.get().strip(),
                entry_point=self.entry_point.get().strip(),
                product_name=self.product_name.get().strip(),
                product_version=self.product_version.get().strip(),
                language=self.selected_language(),
                graphs_directory=str(output_path.parent / "graphs"),
                assessment_callback=assessment_callback,
                progress_callback=self.write,
            )

            # Grava a declaração nos formatos escolhidos.
            written_files = save_analysis(
                analysis,
                output_path,
                self.output_format.get(),
            )

        # Captura os erros previstos pela PoC.
        except VectorError as error:

            # Registra o erro no log.
            self.write(f"\nErro: {error}")

            # Exibe a mensagem em uma caixa de erro.
            #
            # O traceback é omitido porque a mensagem já descreve o
            # problema em termos compreensíveis ao analista.
            messagebox.showerror("Erro na análise", str(error))
            return

        # Reabilita o botão de análise, tanto no sucesso quanto no erro.
        finally:

            # Devolve o botão ao estado normal.
            self.analyze_button.configure(state="normal")

        # Exibe o resumo dos resultados.
        self.show_results(analysis, output_path, written_files)

    # Define o método que exibe o resumo dos resultados.
    def show_results(self, analysis, output_path, written_files):

        # Obtém o resultado da análise estática.
        static_analysis = analysis["static_analysis"]

        # Exibe uma linha em branco.
        self.write("")

        # Exibe o título do grafo.
        self.write("Grafo de chamadas")
        self.write("=" * 60)

        # Percorre o grafo em ordem alfabética.
        for caller, callees in sorted(static_analysis.graph.items()):

            # Exibe a função chamadora e as funções chamadas.
            self.write(f"{caller} -> {', '.join(callees) or '[]'}")

        # Percorre os resultados por vulnerabilidade.
        for result in analysis["results"]:

            # Obtém as evidências registradas.
            evidence = result["evidence"]

            # Exibe uma linha em branco.
            self.write("")

            # Exibe um separador.
            self.write("-" * 60)

            # Exibe a CVE analisada.
            self.write(f"CVE: {result['id']}")

            # Exibe a função vulnerável associada.
            self.write(
                f"Função vulnerável: {result['vulnerable_function']}"
            )

            # Exibe o resultado da análise automática.
            self.write(f"Alcançável: {evidence['reachable']}")

            # Verifica se foi encontrado um caminho.
            if evidence["call_path"]:

                # Exibe o caminho como uma sequência de funções.
                self.write(
                    f"Caminho: {' -> '.join(evidence['call_path'])}"
                )

            # Executa quando nenhum caminho foi encontrado.
            else:

                # Informa que não existe caminho.
                self.write("Caminho: não encontrado")

            # Exibe o estado VEX atribuído.
            self.write(f"Estado VEX: {result['status']}")

            # Exibe a justificativa VEX.
            self.write(f"Justificativa: {result['justification']}")

            # Exibe a conclusão da avaliação.
            self.write(f"Conclusão: {result['detail']}")

        # Exibe uma linha em branco.
        self.write("")

        # Exibe um separador.
        self.write("=" * 60)

        # Percorre os arquivos gravados.
        for written_file in written_files:

            # Informa onde cada declaração foi salva.
            self.write(f"Declaração VEX salva em: {written_file}")

        # Armazena a pasta dos resultados para o botão de abertura.
        self.results_directory = output_path.parent

        # Habilita o botão que abre a pasta dos resultados.
        self.open_button.configure(state="normal")

    # Define o método que abre a pasta dos resultados.
    def open_results_directory(self):
        """
        Abre a pasta dos resultados no gerenciador de arquivos.

        A forma de abrir depende do sistema operacional, por isso a
        chamada é escolhida em tempo de execução.
        """

        # Importa o módulo usado apenas por esta função.
        import subprocess

        # Obtém a pasta armazenada ao final da análise.
        directory = getattr(self, "results_directory", None)

        # Verifica se a pasta existe.
        if directory is None or not Path(directory).exists():

            # Avisa o analista e interrompe a abertura.
            messagebox.showwarning(
                "Pasta não encontrada",
                "A pasta dos resultados ainda não foi criada.",
            )
            return

        # Inicia o tratamento de falhas na abertura.
        try:

            # Executa a abertura conforme o sistema operacional.
            if sys.platform == "win32":

                # No Windows, a função startfile abre a pasta.
                import os

                os.startfile(str(directory))

            # Executa no macOS.
            elif sys.platform == "darwin":

                # O comando open abre a pasta no Finder.
                subprocess.run(["open", str(directory)], check=False)

            # Executa nos demais sistemas, como o Linux.
            else:

                # O comando xdg-open abre a pasta no gerenciador padrão.
                subprocess.run(
                    ["xdg-open", str(directory)],
                    check=False,
                )

        # Captura falhas do sistema operacional.
        except OSError as error:

            # Exibe a mensagem em uma caixa de erro.
            messagebox.showerror(
                "Não foi possível abrir a pasta",
                str(error),
            )


# Define a função que abre a interface gráfica.
def launch():
    """
    Cria a janela principal e inicia o laço de eventos do tkinter.

    Devolve 0 ao encerrar, seguindo a convenção usada pela linha de
    comando para o código de saída do processo.
    """

    # Verifica se o Tk instalado consegue desenhar a interface.
    warning = check_tk_version()

    # Verifica se a versão do Tk é insuficiente.
    if warning is not None:

        # Exibe o aviso no terminal.
        #
        # O aviso vai para o terminal, e não para uma caixa de diálogo,
        # justamente porque a versão problemática do Tk pode não
        # conseguir desenhar a caixa de diálogo.
        print(warning, file=sys.stderr)

    # Cria a janela raiz da aplicação.
    root = tk.Tk()

    # Define o título da janela.
    root.title("Vector — Análise de alcançabilidade e VEX")

    # Define o tamanho inicial da janela.
    root.geometry("900x760")

    # Define o tamanho mínimo, evitando que os campos fiquem cortados.
    root.minsize(760, 600)

    # Cria a janela principal da PoC.
    AnalyzerWindow(root)

    # Inicia o laço de eventos, que só termina quando a janela é
    # fechada pelo analista.
    root.mainloop()

    # Devolve o código de saída de sucesso.
    return 0
