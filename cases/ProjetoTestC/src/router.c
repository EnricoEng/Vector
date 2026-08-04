/*
 * Escolhe o tratador adequado para cada requisição.
 *
 * Elo do caminho vulnerável: router_dispatch -> handler_execute.
 *
 * O ramo alternativo, handle_unknown, existe para que a busca em
 * profundidade precise descartar caminhos que não levam à função
 * vulnerável.
 */

#include <string.h>

#include "../include/handler.h"
#include "../include/logger.h"
#include "../include/router.h"

/* Trata requisições que não correspondem a nenhuma rota conhecida.
 *
 * Não leva à função vulnerável. */
static void handle_unknown(const char *request)
{
    log_error("Rota desconhecida.");

    (void)request;
}

void router_dispatch(const char *request)
{
    log_info("Requisicao recebida.");

    if (strncmp(request, "RUN ", 4) == 0) {
        handler_execute(request + 4);
    } else {
        handle_unknown(request);
    }
}
