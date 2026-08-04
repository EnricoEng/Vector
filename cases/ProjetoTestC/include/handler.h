#ifndef HANDLER_H
#define HANDLER_H

#include <stddef.h>

/* Trata uma requisição já roteada. */
void handler_execute(const char *request);

/* Informa se o conteúdo recebido está vazio.
 *
 * Diferente das demais funções deste cabeçalho, esta possui corpo e não
 * apenas protótipo. Existe para verificar que a análise reconhece
 * definições declaradas dentro de arquivos .h, e não somente as que
 * estão em arquivos .c. */
static inline int payload_is_empty(const char *payload)
{
    return payload == NULL || payload[0] == '\0';
}

#endif
