#ifndef ROUTER_H
#define ROUTER_H

/* Escolhe o tratador adequado para a requisição recebida. */
void router_dispatch(const char *request);

#endif
