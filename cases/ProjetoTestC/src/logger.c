/*
 * Registro de eventos da aplicação.
 *
 * Nenhuma função deste arquivo participa do caminho vulnerável. Elas
 * são chamadas a partir de vários pontos do projeto e existem para que
 * o grafo possua ramos que a busca precisa percorrer e descartar.
 */

#include <stdio.h>

#include "../include/logger.h"

/* Escreve uma linha já formatada na saída indicada.
 *
 * Concentra a escrita usada por log_info e log_error. */
static void write_line(FILE *stream, const char *level, const char *message)
{
    fprintf(stream, "[%s] %s\n", level, message);
}

void log_init(void)
{
    write_line(stdout, "INFO", "Registro iniciado.");
}

void log_info(const char *message)
{
    write_line(stdout, "INFO", message);
}

void log_error(const char *message)
{
    write_line(stderr, "ERRO", message);
}
