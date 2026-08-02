# Desenha a logo da ferramenta em um widget Canvas do tkinter.
#
# A logo é desenhada com primitivas do próprio Canvas, e não carregada
# de um arquivo de imagem. Essa decisão tem três motivos:
#
# 1. o tkinter só carrega PNG a partir do Tk 8.6, e o Tk distribuído
#    com o macOS ainda é o 8.5;
# 2. não exige que um arquivo externo acompanhe o programa;
# 3. o desenho acompanha qualquer tamanho sem perder definição.
#
# O desenho reproduz o arquivo assets/logo.svg. As coordenadas são
# escritas em uma área de referência de 512 por 512 e convertidas para o
# tamanho pedido, do mesmo modo que o atributo viewBox de um SVG.

# Importa Path para localizar os arquivos de imagem.
from pathlib import Path


# Define o lado da área de referência usada nas coordenadas.
REFERENCE_SIZE = 512


# Define a pasta que contém as imagens da logo.
ASSETS_DIRECTORY = Path(__file__).resolve().parent.parent / "assets"


# Define os tamanhos disponíveis em imagem.
AVAILABLE_IMAGE_SIZES = [64, 128, 512]


# Define a versão mínima do Tk capaz de carregar arquivos PNG.
#
# O suporte a PNG só foi acrescentado ao Tk na versão 8.6. Nas versões
# anteriores, entre elas a que acompanha o macOS, a logo precisa ser
# desenhada no Canvas.
MINIMUM_PNG_TK_VERSION = 8.6


# Define a função que carrega a logo em imagem.
def load_logo_image(size):
    """
    Carrega a logo a partir de um arquivo PNG.

    Devolve um objeto PhotoImage, ou None quando a imagem não pode ser
    usada. Nesse caso, o chamador deve recorrer ao desenho no Canvas.

    A imagem é preferida ao desenho porque o Canvas do Tk não aplica
    antialiasing no Windows: diagonais e círculos ficariam serrilhados.
    Os arquivos PNG são gerados com suavização verdadeira por
    tools/render_logo.py.

    Importante: o objeto devolvido precisa ser mantido referenciado pelo
    chamador. O tkinter não guarda referência às imagens, e uma imagem
    coletada pelo gerenciador de memória simplesmente desaparece da tela.
    """

    # Importa o tkinter apenas quando a função é chamada.
    import tkinter as tk

    # Verifica se a versão do Tk suporta arquivos PNG.
    if tk.TkVersion < MINIMUM_PNG_TK_VERSION:
        return None

    # Procura o menor tamanho disponível que atenda ao pedido, para que
    # a imagem nunca precise ser ampliada.
    candidates = [s for s in AVAILABLE_IMAGE_SIZES if s >= size]

    # Usa o maior tamanho existente quando nenhum atende.
    chosen = min(candidates) if candidates else max(AVAILABLE_IMAGE_SIZES)

    # Monta o caminho do arquivo.
    path = ASSETS_DIRECTORY / f"logo-{chosen}.png"

    # Verifica se o arquivo existe.
    if not path.is_file():
        return None

    # Inicia o tratamento de falhas de leitura.
    try:

        # Carrega a imagem.
        image = tk.PhotoImage(file=str(path))

    # Captura formatos não suportados e erros de leitura.
    except (tk.TclError, OSError):

        # Informa que a imagem não pôde ser usada.
        return None

    # Verifica se a imagem precisa ser reduzida.
    #
    # O método subsample aceita apenas fatores inteiros, por isso a
    # redução só é feita quando o tamanho é um divisor exato.
    if chosen > size and chosen % size == 0:
        image = image.subsample(chosen // size)

    # Devolve a imagem carregada.
    return image


# Define as cores da logo.
#
# As três cores do caminho são as mesmas utilizadas pelos grafos que a
# ferramenta gera: azul para o ponto de entrada, verde para o caminho
# percorrido e vermelho para a função vulnerável.
COLORS = {
    "badge": "#16213A",
    "badge_border": "#334155",
    "inactive": "#334155",
    "entry_fill": "#DBEAFE",
    "entry_border": "#2563EB",
    "path_fill": "#DCFCE7",
    "path_border": "#16A34A",
    "arrow": "#EF4444",
}


# Define as paradas de cor do caminho, do início ao fim.
#
# A parada âmbar existe por dois motivos. O primeiro é visual: a
# interpolação direta entre verde e vermelho atravessa tons de oliva e
# marrom, que sujam o gradiente. O segundo é de significado: com ela, o
# caminho passa a ser lido como uma escalada de risco até a função
# vulnerável.
PATH_STOPS = ["#3B82F6", "#22C55E", "#F59E0B", "#EF4444"]


# As constantes a seguir descrevem a geometria da logo na área de
# referência de 512 por 512.
#
# Elas ficam reunidas aqui porque são usadas em dois lugares: pelo
# desenho no Canvas, mais abaixo, e pelo gerador da imagem PNG, em
# tools/render_logo.py. Manter uma única definição impede que os dois
# desenhos divirjam com o tempo.

# Emblema de fundo, no formato (x0, y0, x1, y1, raio dos cantos).
BADGE = (32, 32, 480, 480, 104)

# Arestas do grafo que a busca não percorreu.
INACTIVE_EDGES = [
    (132, 330, 150, 170),
    (256, 372, 366, 330),
]

# Nós que não pertencem ao caminho encontrado, com o respectivo raio.
INACTIVE_NODES = [(132, 330), (366, 330), (256, 118)]
INACTIVE_NODE_RADIUS = 13

# Caminho de alcançabilidade, do ponto de entrada até a ponta da seta.
PATH_POINTS = [(150, 140), (256, 372), (365, 159)]
PATH_WIDTH = 34

# Ponta do vetor, sobre a função vulnerável.
ARROW_POINTS = [(386, 118), (338.3, 145.2), (391.7, 172.6)]

# Nó do ponto de entrada, no formato (x, y, raio, espessura da borda).
ENTRY_NODE = (150, 140, 30, 11)

# Nó intermediário, pertencente ao caminho.
PATH_NODE = (256, 372, 25, 10)


# Define a função que converte uma cor hexadecimal em três componentes.
def parse_color(color):

    # Remove o caractere inicial e separa os pares hexadecimais.
    color = color.lstrip("#")

    # Converte cada par em um número inteiro entre 0 e 255.
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


# Define a função que calcula uma cor intermediária.
def blend_colors(stops, position):
    """
    Devolve a cor correspondente a uma posição do gradiente.

    A posição varia de 0.0, no início, até 1.0, no fim. O tkinter não
    possui gradiente nativo, por isso o caminho é desenhado como uma
    sequência de segmentos curtos, cada um com a cor calculada aqui.
    """

    # Limita a posição ao intervalo válido.
    position = max(0.0, min(1.0, position))

    # Calcula em qual trecho entre duas paradas a posição se encontra.
    scaled = position * (len(stops) - 1)

    # Obtém o índice da parada anterior.
    index = min(int(scaled), len(stops) - 2)

    # Calcula a posição relativa dentro do trecho.
    local = scaled - index

    # Obtém as componentes das duas paradas envolvidas.
    start = parse_color(stops[index])
    end = parse_color(stops[index + 1])

    # Interpola cada componente e monta a cor final.
    return "#%02X%02X%02X" % tuple(
        round(start[i] + (end[i] - start[i]) * local)
        for i in range(3)
    )


# Define a função que desenha um retângulo de cantos arredondados.
def draw_rounded_rectangle(canvas, x0, y0, x1, y1, radius, **options):
    """
    Desenha um retângulo arredondado no Canvas.

    O Canvas não possui essa forma entre suas primitivas. O contorno é
    montado como um polígono cujos vértices se repetem nos cantos e é
    desenhado com suavização, o que produz o arredondamento.
    """

    # Monta os pontos do contorno, repetindo os vértices dos cantos.
    points = [
        x0 + radius, y0,
        x1 - radius, y0,
        x1, y0,
        x1, y0 + radius,
        x1, y1 - radius,
        x1, y1,
        x1 - radius, y1,
        x0 + radius, y1,
        x0, y1,
        x0, y1 - radius,
        x0, y0 + radius,
        x0, y0,
    ]

    # Desenha o polígono suavizado.
    return canvas.create_polygon(points, smooth=True, **options)


# Define a função que desenha uma linha com gradiente.
def draw_gradient_path(canvas, points, stops, width, steps=48):
    """
    Desenha uma sequência de pontos aplicando um gradiente de cor.

    O caminho é dividido em segmentos de comprimento proporcional, e
    cada segmento recebe a cor correspondente à sua posição.
    """

    # Calcula o comprimento de cada trecho entre pontos consecutivos.
    lengths = []

    # Percorre os pares de pontos consecutivos.
    for index in range(len(points) - 1):

        # Obtém as coordenadas dos dois pontos.
        x0, y0 = points[index]
        x1, y1 = points[index + 1]

        # Calcula a distância entre eles.
        lengths.append(((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5)

    # Calcula o comprimento total do caminho.
    total = sum(lengths)

    # Interrompe o desenho quando o caminho não possui extensão.
    if total == 0:
        return

    # Inicializa a distância já percorrida.
    walked = 0.0

    # Percorre novamente os trechos do caminho.
    for index in range(len(points) - 1):

        # Obtém as coordenadas do trecho atual.
        x0, y0 = points[index]
        x1, y1 = points[index + 1]

        # Calcula quantos segmentos este trecho receberá,
        # proporcionalmente ao seu comprimento.
        count = max(1, round(steps * lengths[index] / total))

        # Desenha os segmentos do trecho.
        for step in range(count):

            # Calcula as frações inicial e final do segmento.
            start_fraction = step / count
            end_fraction = (step + 1) / count

            # Calcula as coordenadas do segmento.
            segment_x0 = x0 + (x1 - x0) * start_fraction
            segment_y0 = y0 + (y1 - y0) * start_fraction
            segment_x1 = x0 + (x1 - x0) * end_fraction
            segment_y1 = y0 + (y1 - y0) * end_fraction

            # Calcula a posição do segmento dentro do caminho inteiro.
            position = (
                walked + lengths[index] * (start_fraction + end_fraction) / 2
            ) / total

            # Desenha o segmento com a cor correspondente.
            #
            # As extremidades arredondadas fazem os segmentos se
            # sobreporem, evitando falhas visíveis entre eles.
            canvas.create_line(
                segment_x0,
                segment_y0,
                segment_x1,
                segment_y1,
                fill=blend_colors(stops, position),
                width=width,
                capstyle="round",
            )

        # Acumula o comprimento do trecho já desenhado.
        walked += lengths[index]


# Define a função que desenha a logo.
def draw_logo(canvas, size):
    """
    Desenha a logo ocupando uma área quadrada de lado "size".

    O desenho reproduz assets/logo.svg: um caminho de alcançabilidade
    que parte do ponto de entrada, atravessa uma função intermediária e
    termina em uma ponta de seta sobre a função vulnerável, formando ao
    mesmo tempo a letra V de Vector.
    """

    # Calcula o fator de conversão entre a área de referência e o
    # tamanho pedido.
    scale = size / REFERENCE_SIZE

    # Define uma função interna que converte uma coordenada.
    def at(value):
        return value * scale

    # Define uma função interna que converte um par de coordenadas.
    def point(x, y):
        return (at(x), at(y))

    # Desenha o emblema de fundo.
    draw_rounded_rectangle(
        canvas,
        at(BADGE[0]),
        at(BADGE[1]),
        at(BADGE[2]),
        at(BADGE[3]),
        at(BADGE[4]),
        fill=COLORS["badge"],
        outline=COLORS["badge_border"],
        width=max(1, at(3)),
    )

    # Desenha as arestas que a busca não percorreu.
    #
    # Elas ficam em cinza para representar o restante do grafo de
    # chamadas, que existe mas não pertence ao caminho encontrado.
    for x0, y0, x1, y1 in INACTIVE_EDGES:
        canvas.create_line(
            at(x0),
            at(y0),
            at(x1),
            at(y1),
            fill=COLORS["inactive"],
            width=max(1, at(6)),
            capstyle="round",
        )

    # Desenha os nós que não pertencem ao caminho.
    for x, y in INACTIVE_NODES:
        canvas.create_oval(
            at(x - INACTIVE_NODE_RADIUS),
            at(y - INACTIVE_NODE_RADIUS),
            at(x + INACTIVE_NODE_RADIUS),
            at(y + INACTIVE_NODE_RADIUS),
            fill=COLORS["inactive"],
            outline="",
        )

    # Desenha o caminho de alcançabilidade com o gradiente de cores.
    draw_gradient_path(
        canvas,
        [point(x, y) for x, y in PATH_POINTS],
        PATH_STOPS,
        width=max(2, at(PATH_WIDTH)),
    )

    # Desenha a ponta do vetor, sobre a função vulnerável.
    arrow = []
    for x, y in ARROW_POINTS:
        arrow.extend([at(x), at(y)])
    canvas.create_polygon(
        arrow,
        fill=COLORS["arrow"],
        outline="",
    )

    # Desenha os dois nós pertencentes ao caminho.
    for (x, y, radius, border), fill, outline in (
        (ENTRY_NODE, COLORS["entry_fill"], COLORS["entry_border"]),
        (PATH_NODE, COLORS["path_fill"], COLORS["path_border"]),
    ):
        canvas.create_oval(
            at(x - radius),
            at(y - radius),
            at(x + radius),
            at(y + radius),
            fill=fill,
            outline=outline,
            width=max(1, at(border)),
        )
