"""Ponto de entrada da aplicação.

Este arquivo não contém nenhuma função vulnerável. O caminho até ela só
aparece quando os grafos de todos os arquivos do projeto são unidos em
um único grafo de chamadas.
"""

from logger import log_init
from server import server_start


def main():
    """Prepara o registro e inicia o servidor."""
    log_init()

    server_start()


if __name__ == "__main__":
    main()
