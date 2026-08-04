"""Recebe as requisições e as encaminha ao roteador.

Elo do caminho vulnerável: server_start -> router_dispatch.
"""

import sys

from logger import log_info
from router import router_dispatch


def read_request():
    """Lê uma requisição da entrada padrão.

    Não participa do caminho vulnerável: apenas obtém os dados. Devolve
    None quando a entrada termina.
    """
    return sys.stdin.readline() or None


def server_start():
    """Executa o laço que recebe e encaminha as requisições."""
    log_info("Servidor iniciado.")

    while True:
        request = read_request()

        if request is None:
            break

        router_dispatch(request)

    log_info("Servidor encerrado.")
