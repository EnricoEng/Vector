/*
 * Caso controlado em C: função vulnerável alcançável e explorável.
 *
 * O caminho esperado pela análise de alcançabilidade é:
 *
 *     main -> process_request -> parse_request -> vulnerable_function
 *
 */

#include <stdio.h>
#include <stdlib.h>

/* Função associada à vulnerabilidade. */

int vulnerable_function(const char *user_input)
{
    return system(user_input);
}


static int parse_request(const char *user_input)
{
    return vulnerable_function(user_input);
}


static int process_request(const char *user_input)
{
    return parse_request(user_input);
}

/* Função de apoio que não participa do caminho vulnerável.
 *
 * Existe para que o grafo possua um ramo alternativo, demonstrando que
 * a busca em profundidade percorre apenas o caminho relevante. */
static void helper(void)
{
    printf("Operacao helper\n");
}


/* Ponto de entrada da aplicação. */
int main(void)
{
    char user_input[256];

    helper();

    if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
        return 1;
    }

    process_request(user_input);

    return 0;
}
