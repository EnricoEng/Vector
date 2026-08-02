/*
 * Caso controlado em C: função vulnerável presente, porém não
 * alcançável a partir do ponto de entrada.
 *
 * A função vulnerable_function está declarada no arquivo, mas nenhuma
 * cadeia de chamadas parte de main() e chega até ela. A análise deve
 * classificar a vulnerabilidade como:
 *
 *     NOT_AFFECTED / code_not_reachable
 *
 */

#include <stdio.h>
#include <stdlib.h>

/* Função associada à vulnerabilidade.
 *
 * Permanece no código, mas nunca é chamada a partir do ponto de
 * entrada. É o caso típico de uma dependência presente no binário e
 * ausente do fluxo de execução. */
int vulnerable_function(const char *user_input)
{
    return system(user_input);
}


static void helper(void)
{
    printf("Operacao segura\n");
}


static void process_request(void)
{
    helper();
}


/* Ponto de entrada da aplicação. */
int main(void)
{
    process_request();

    return 0;
}
