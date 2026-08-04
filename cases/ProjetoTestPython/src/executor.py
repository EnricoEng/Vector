"""Executa o comando recebido.

Último elo do caminho vulnerável: run_command -> vulnerable_function.

A função vulnerável está declarada aqui, e o ponto de entrada está em
src/main.py. Analisar qualquer um dos dois arquivos isoladamente não
revela o caminho entre eles.
"""

from logger import log_info


def vulnerable_function(command):
    """Função associada à vulnerabilidade.

    Entrega ao eval() um texto originado da requisição, sem qualquer
    validação.
    """
    print("Entrou na vulnerable_function")

    return eval(command)


def run_command(command):
    """Encaminha o comando para execução."""
    log_info("Executando comando.")

    return vulnerable_function(command)
