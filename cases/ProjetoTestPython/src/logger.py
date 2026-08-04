"""Registro de eventos da aplicação.

Nenhuma função deste módulo participa do caminho vulnerável. Elas são
chamadas a partir de vários pontos do projeto e existem para que o grafo
possua ramos que a busca precisa percorrer e descartar.
"""

import sys


def write_line(stream, level, message):
    """Escreve uma linha já formatada na saída indicada."""
    print(f"[{level}] {message}", file=stream)


def log_init():
    """Prepara o registro de eventos da aplicação."""
    write_line(sys.stdout, "INFO", "Registro iniciado.")


def log_info(message):
    """Registra uma mensagem informativa."""
    write_line(sys.stdout, "INFO", message)


def log_error(message):
    """Registra uma mensagem de erro."""
    write_line(sys.stderr, "ERRO", message)
