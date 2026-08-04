/*
 * Recebe as requisições e as encaminha ao roteador.
 *
 * Elo do caminho vulnerável: server_start -> router_dispatch.
 */

#include <stdio.h>

#include "../include/logger.h"
#include "../include/router.h"
#include "../include/server.h"

/* Lê uma requisição da entrada padrão.
 *
 * Não participa do caminho vulnerável: apenas obtém os dados. */
static int read_request(char *buffer, int size)
{
    if (fgets(buffer, size, stdin) == NULL) {
        return 0;
    }

    return 1;
}

void server_start(void)
{
    char buffer[512];

    log_info("Servidor iniciado.");

    while (read_request(buffer, sizeof(buffer))) {
        router_dispatch(buffer);
    }

    log_info("Servidor encerrado.");
}
