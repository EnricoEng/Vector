# Gera os arquivos PNG da logo a partir da geometria definida em
# vector/logo.py.
#
# Este script não é executado pela ferramenta. Ele é utilizado apenas
# quando a logo muda, para regravar as imagens em assets/. Os PNGs são
# versionados no repositório, de modo que o Pillow não é uma dependência
# de execução da PoC.
#
# Motivo de existir uma versão em imagem, já que a logo também é
# desenhada diretamente no Canvas:
#
# O Canvas do Tk não aplica antialiasing no Windows, onde o desenho usa
# a GDI. Diagonais e círculos ficam serrilhados. Uma imagem preparada
# com antialiasing verdadeiro contorna essa limitação. O desenho no
# Canvas permanece como alternativa para quando o PNG não pode ser
# carregado, o que ocorre no Tk 8.5.
#
# A suavização é obtida desenhando em uma resolução várias vezes maior e
# reduzindo a imagem em seguida, técnica conhecida como supersampling.
#
# Uso:
#     python tools/render_logo.py

# Importa o módulo sys, utilizado para ajustar o caminho de importação.
import sys

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path

# Acrescenta a raiz do projeto ao caminho de importação, permitindo
# executar o script diretamente de qualquer diretório.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Importa as ferramentas de desenho do Pillow.
from PIL import Image, ImageDraw

# Importa a geometria e as cores compartilhadas com o desenho no Canvas.
from vector.logo import (
    ARROW_POINTS,
    BADGE,
    COLORS,
    ENTRY_NODE,
    INACTIVE_EDGES,
    INACTIVE_NODES,
    INACTIVE_NODE_RADIUS,
    PATH_POINTS,
    PATH_STOPS,
    PATH_WIDTH,
    PATH_NODE,
    REFERENCE_SIZE,
    blend_colors,
)


# Define o fator de supersampling.
#
# O desenho é feito em uma resolução quatro vezes maior e reduzido em
# seguida, o que produz bordas suaves.
SUPERSAMPLE = 4

# Define os tamanhos gerados.
#
# O tamanho 64 é o usado no cabeçalho da janela. O 128 atende telas com
# fator de escala elevado. O 512 serve como imagem de uso geral.
SIZES = [64, 128, 512]


# Define a função que desenha a logo em uma imagem do Pillow.
def render(size):
    """
    Desenha a logo e devolve uma imagem de lado "size".
    """

    # Calcula o lado da imagem ampliada.
    large = size * SUPERSAMPLE

    # Calcula o fator de conversão da área de referência.
    scale = large / REFERENCE_SIZE

    # Define uma função interna que converte uma coordenada.
    def at(value):
        return value * scale

    # Cria a imagem ampliada com fundo transparente.
    image = Image.new("RGBA", (large, large), (0, 0, 0, 0))

    # Cria o objeto de desenho.
    draw = ImageDraw.Draw(image)

    # Desenha o emblema de fundo.
    draw.rounded_rectangle(
        [at(BADGE[0]), at(BADGE[1]), at(BADGE[2]), at(BADGE[3])],
        radius=at(BADGE[4]),
        fill=COLORS["badge"],
        outline=COLORS["badge_border"],
        width=max(1, round(at(3))),
    )

    # Desenha as arestas que a busca não percorreu.
    for x0, y0, x1, y1 in INACTIVE_EDGES:
        draw.line(
            [at(x0), at(y0), at(x1), at(y1)],
            fill=COLORS["inactive"],
            width=max(1, round(at(6))),
        )

    # Desenha os nós que não pertencem ao caminho.
    for x, y in INACTIVE_NODES:
        draw.ellipse(
            [
                at(x - INACTIVE_NODE_RADIUS),
                at(y - INACTIVE_NODE_RADIUS),
                at(x + INACTIVE_NODE_RADIUS),
                at(y + INACTIVE_NODE_RADIUS),
            ],
            fill=COLORS["inactive"],
        )

    # Desenha o caminho com o gradiente de cores.
    draw_gradient(draw, at)

    # Desenha a ponta do vetor.
    draw.polygon(
        [(at(x), at(y)) for x, y in ARROW_POINTS],
        fill=COLORS["arrow"],
    )

    # Desenha os dois nós pertencentes ao caminho.
    for (x, y, radius, border), fill, outline in (
        (ENTRY_NODE, COLORS["entry_fill"], COLORS["entry_border"]),
        (PATH_NODE, COLORS["path_fill"], COLORS["path_border"]),
    ):
        draw.ellipse(
            [
                at(x - radius),
                at(y - radius),
                at(x + radius),
                at(y + radius),
            ],
            fill=fill,
            outline=outline,
            width=max(1, round(at(border))),
        )

    # Reduz a imagem ao tamanho final.
    #
    # O filtro LANCZOS calcula a média ponderada dos pixels vizinhos, o
    # que converte a resolução extra em bordas suaves.
    return image.resize((size, size), Image.LANCZOS)


# Define a função que desenha o caminho com gradiente.
def draw_gradient(draw, at, steps=240):
    """
    Desenha o caminho como uma sequência de segmentos coloridos.

    O Pillow não possui gradiente ao longo de um traçado, por isso o
    caminho é dividido em segmentos curtos. O número de segmentos é
    maior do que o usado no Canvas porque o desenho ocorre na resolução
    ampliada.
    """

    # Converte os pontos do caminho para a escala da imagem.
    points = [(at(x), at(y)) for x, y in PATH_POINTS]

    # Calcula o comprimento de cada trecho.
    lengths = [
        (
            (points[i + 1][0] - points[i][0]) ** 2
            + (points[i + 1][1] - points[i][1]) ** 2
        )
        ** 0.5
        for i in range(len(points) - 1)
    ]

    # Calcula o comprimento total do caminho.
    total = sum(lengths)

    # Calcula a espessura do traço.
    width = max(1, round(at(PATH_WIDTH)))

    # Inicializa a distância já percorrida.
    walked = 0.0

    # Percorre os trechos do caminho.
    for index in range(len(points) - 1):

        # Obtém as coordenadas do trecho atual.
        x0, y0 = points[index]
        x1, y1 = points[index + 1]

        # Calcula quantos segmentos este trecho receberá.
        count = max(1, round(steps * lengths[index] / total))

        # Desenha os segmentos do trecho.
        for step in range(count):

            # Calcula as frações inicial e final do segmento.
            start = step / count
            end = (step + 1) / count

            # Calcula a posição do segmento no caminho inteiro.
            position = (
                walked + lengths[index] * (start + end) / 2
            ) / total

            # Obtém a cor correspondente à posição.
            color = blend_colors(PATH_STOPS, position)

            # Desenha o segmento.
            draw.line(
                [
                    x0 + (x1 - x0) * start,
                    y0 + (y1 - y0) * start,
                    x0 + (x1 - x0) * end,
                    y0 + (y1 - y0) * end,
                ],
                fill=color,
                width=width,
            )

            # Desenha um círculo na junção dos segmentos.
            #
            # O Pillow não arredonda as pontas das linhas, e sem esse
            # círculo apareceriam falhas entre um segmento e o seguinte,
            # além de cantos vivos na dobra do caminho.
            cx = x0 + (x1 - x0) * end
            cy = y0 + (y1 - y0) * end
            radius = width / 2
            draw.ellipse(
                [cx - radius, cy - radius, cx + radius, cy + radius],
                fill=color,
            )

        # Acumula o comprimento do trecho já desenhado.
        walked += lengths[index]


# Define a função principal do script.
def main():

    # Determina a pasta que receberá as imagens.
    assets = Path(__file__).resolve().parent.parent / "assets"

    # Cria a pasta caso ainda não exista.
    assets.mkdir(parents=True, exist_ok=True)

    # Percorre os tamanhos solicitados.
    for size in SIZES:

        # Desenha a logo no tamanho atual.
        image = render(size)

        # Monta o caminho do arquivo.
        output = assets / f"logo-{size}.png"

        # Grava a imagem.
        image.save(output)

        # Informa o arquivo gerado.
        print(f"Gerado: {output}")


# Verifica se o arquivo está sendo executado diretamente.
if __name__ == "__main__":
    main()
