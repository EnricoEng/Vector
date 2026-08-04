/*
 * Ponto de entrada da aplicação.
 *
 * Este arquivo não contém nenhuma função vulnerável. O caminho até ela
 * só aparece quando os grafos de todos os arquivos do projeto são
 * unidos em um único grafo de chamadas.
 */

#include "../include/logger.h"
#include "../include/server.h"

int main(void)
{
    log_init();

    server_start();

    return 0;
}
