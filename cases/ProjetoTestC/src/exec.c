/*
 * Executa o comando recebido.
 *
 * Último elo do caminho vulnerável: run_command -> vulnerable_function.
 *
 * A função vulnerável está declarada aqui, e o ponto de entrada está em
 * src/main.c. Analisar qualquer um dos dois arquivos isoladamente não
 * revela o caminho entre eles.
 */

#include <stdlib.h>
#include <stdio.h>

#include "../include/exec.h"
#include "../include/logger.h"

/* Função associada à vulnerabilidade.
 *
 * Entrega ao interpretador de comandos do sistema um texto originado da
 * requisição, sem qualquer validação. */
int vulnerable_function(const char *command)
{
    printf("Entrou na vulnerable_function");
    return system(command);
}

int run_command(const char *command)
{
    log_info("Executando comando.");

    return vulnerable_function(command);
}
