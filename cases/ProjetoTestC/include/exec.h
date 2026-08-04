#ifndef EXEC_H
#define EXEC_H

/* Executa um comando montado a partir da requisição. */
int run_command(const char *command);

/* Função associada à vulnerabilidade. */
int vulnerable_function(const char *command);

#endif
