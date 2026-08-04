/*
 * Trata a requisição já roteada e aciona a execução do comando.
 *
 * Elo do caminho vulnerável: handler_execute -> run_command.
 */

#include "../include/exec.h"
#include "../include/handler.h"
#include "../include/logger.h"

/* Extrai o conteúdo da requisição, removendo a quebra de linha final.
 *
 * Não participa do caminho vulnerável: apenas prepara o texto. */
static char *parse_payload(char *request)
{
    char *cursor = request;

    while (*cursor != '\0') {
        if (*cursor == '\n') {
            *cursor = '\0';
            break;
        }

        cursor++;
    }

    return request;
}

void handler_execute(const char *request)
{
    char *payload = parse_payload((char *)request);

    if (payload_is_empty(payload)) {
        log_error("Requisicao sem conteudo.");
        return;
    }

    run_command(payload);
}
