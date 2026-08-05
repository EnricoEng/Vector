# Deriva os pontos de entrada de uma biblioteca a partir de quem a usa.
#
# Este script implementa o estágio 1 da análise em dois estágios, usada
# quando a aplicação não chama a biblioteca vulnerável diretamente.
#
# O problema que ele resolve:
#
# Ao analisar uma biblioteca isoladamente, não existe um "main". Toda
# função pública é um começo possível de execução, e usar todas produz
# uma análise pessimista, que considera alcançável qualquer coisa que a
# biblioteca faça — inclusive o que o programa real nunca aciona.
#
# O ponto de entrada correto é o conjunto de funções que o consumidor
# efetivamente chama. Este script descobre esse conjunto analisando o
# código do consumidor, e grava o resultado no formato aceito pelo
# argumento --entry do analyzer.py.
#
# As duas camadas costumam estar em linguagens diferentes: uma aplicação
# em C++ que consome uma biblioteca em C, por exemplo. Por isso a
# linguagem de cada lado é informada separadamente.
#
# Uso:
#
#     python tools/derive_entry_points.py \
#         --consumer caminho/da/aplicacao \
#         --consumer-language cpp \
#         --library caminho/da/biblioteca \
#         --library-language c \
#         --output entry_points.txt
#
# O consumidor e a biblioteca precisam ser pastas distintas. Informar a
# mesma pasta nos dois lados devolveria apenas as chamadas internas da
# biblioteca, e por isso é recusado.

# Importa o módulo argparse, utilizado para receber argumentos
# informados pela linha de comando.
import argparse

# Importa o módulo sys, utilizado para ajustar o caminho de importação
# e para encerrar o programa com um código de saída adequado.
import sys

# Importa Path para manipular caminhos de arquivos.
from pathlib import Path

# Acrescenta a raiz do projeto ao caminho de importação, permitindo
# executar o script diretamente de qualquer diretório.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Importa a exceção base, usada para tratar os erros previstos.
from vector.errors import VectorError

# Importa a derivação de pontos de entrada.
#
# A implementação fica no pacote vector, e não aqui, para que a
# interface gráfica use exatamente a mesma lógica.
from vector.reachability import derive_entry_points


# Define a função que monta o interpretador de argumentos.
def build_parser():

    # Cria o analisador dos argumentos de linha de comando.
    parser = argparse.ArgumentParser(
        description=(
            "Deriva os pontos de entrada de uma biblioteca a partir do "
            "código que a consome, para uso no argumento --entry do "
            "analyzer.py."
        )
    )

    # Adiciona o argumento que informa o código do consumidor.
    parser.add_argument(
        "--consumer",
        required=True,
        help="Pasta com o código que consome a biblioteca.",
    )

    # Adiciona o argumento que informa a linguagem do consumidor.
    parser.add_argument(
        "--consumer-language",
        help=(
            "Linguagem do consumidor. Quando omitida, é detectada "
            "automaticamente."
        ),
    )

    # Adiciona o argumento que informa o código da biblioteca.
    parser.add_argument(
        "--library",
        required=True,
        help="Pasta com o código da biblioteca analisada.",
    )

    # Adiciona o argumento que informa a linguagem da biblioteca.
    parser.add_argument(
        "--library-language",
        help=(
            "Linguagem da biblioteca. Quando omitida, é detectada "
            "automaticamente."
        ),
    )

    # Adiciona o argumento que informa o arquivo de saída.
    parser.add_argument(
        "--output",
        help=(
            "Arquivo que receberá a lista. Quando omitido, a lista é "
            "escrita na saída padrão."
        ),
    )

    # Retorna o interpretador montado.
    return parser


# Define a função principal do script.
def main():

    # Processa os argumentos fornecidos pelo usuário.
    args = build_parser().parse_args()

    # Inicia o tratamento dos erros previstos.
    try:

        # Deriva os pontos de entrada.
        entradas, consumidor, biblioteca, avisos = derive_entry_points(
            consumer=args.consumer,
            library=args.library,
            consumer_language=args.consumer_language,
            library_language=args.library_language,
        )

    # Captura os erros previstos pela PoC.
    except VectorError as error:

        # Exibe a mensagem no fluxo de erro padrão.
        print(f"Erro: {error}", file=sys.stderr)

        # Encerra o programa indicando falha.
        return 1

    # Monta a linha no formato aceito pelo argumento --entry.
    linha = ",".join(entradas)

    # Relata os números encontrados no fluxo de erro padrão.
    #
    # O relato vai para o stderr, e não para o stdout, de modo que a
    # saída do script possa ser encaminhada diretamente ao analyzer.py
    # sem que as mensagens se misturem à lista.
    print(
        f"Consumidor : {len(consumidor.sources)} arquivo(s), "
        f"{len(consumidor.functions)} função(ões) declarada(s)",
        file=sys.stderr,
    )
    print(
        f"Biblioteca : {len(biblioteca.sources)} arquivo(s), "
        f"{len(biblioteca.functions)} função(ões) declarada(s)",
        file=sys.stderr,
    )
    print(
        f"Pontos de entrada derivados: {len(entradas)}",
        file=sys.stderr,
    )

    # Exibe os avisos produzidos pela derivação.
    for aviso in avisos:
        print(f"Aviso: {aviso}", file=sys.stderr)

    # Verifica se nenhuma função em comum foi encontrada.
    if not entradas:

        # Alerta o analista, pois o resultado provavelmente indica um
        # erro nos caminhos informados.
        print(
            "Aviso: o consumidor não chama nenhuma função declarada "
            "na biblioteca. Verifique os caminhos e as linguagens "
            "informadas.",
            file=sys.stderr,
        )

    # Verifica se um arquivo de saída foi informado.
    if args.output:

        # Grava a lista no arquivo.
        Path(args.output).write_text(linha + "\n", encoding="utf-8")

        # Informa onde a lista foi gravada.
        print(f"Gravado em: {args.output}", file=sys.stderr)

    # Executa quando nenhum arquivo foi informado.
    else:

        # Escreve a lista na saída padrão.
        print(linha)

    # Encerra o programa indicando sucesso.
    return 0


# Verifica se o arquivo está sendo executado diretamente.
if __name__ == "__main__":

    # Executa a função principal e encerra o processo com o
    # código de saída devolvido por ela.
    sys.exit(main())
