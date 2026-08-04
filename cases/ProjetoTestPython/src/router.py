"""Escolhe o tratador adequado para cada requisição.

Elo do caminho vulnerável: router_dispatch -> handler_execute.

O ramo alternativo, handle_unknown, existe para que a busca em
profundidade precise descartar caminhos que não levam à função
vulnerável.
"""

from handler import handler_execute
from logger import log_error, log_info


def handle_unknown(request):
    """Trata requisições que não correspondem a nenhuma rota conhecida.

    Não leva à função vulnerável.
    """
    log_error("Rota desconhecida.")


def router_dispatch(request):
    """Encaminha a requisição conforme o seu prefixo."""
    log_info("Requisicao recebida.")

    if request.startswith("RUN "):
        return handler_execute(request[4:])

    return handle_unknown(request)
