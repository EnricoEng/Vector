"""Trata a requisição já roteada e aciona a execução do comando.

Elo do caminho vulnerável: handler_execute -> run_command.
"""

from executor import run_command
from logger import log_error


def parse_payload(request):
    """Remove espaços e a quebra de linha final da requisição.

    Não participa do caminho vulnerável: apenas prepara o texto.
    """
    return request.strip()


def payload_is_empty(payload):
    """Informa se o conteúdo recebido está vazio."""
    return payload is None or payload == ""


def handler_execute(request):
    """Prepara o conteúdo e aciona a execução."""
    payload = parse_payload(request)

    if payload_is_empty(payload):
        log_error("Requisicao sem conteudo.")
        return None

    return run_command(payload)
