#ifndef LOGGER_H
#define LOGGER_H

/* Prepara o registro de eventos da aplicação. */
void log_init(void);

/* Registra uma mensagem informativa. */
void log_info(const char *message);

/* Registra uma mensagem de erro. */
void log_error(const char *message);

#endif
