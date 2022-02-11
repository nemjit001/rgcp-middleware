#ifndef LOGGER
#define LOGGER

#include <stdarg.h>
#include <stdio.h>

enum LOG_LEVEL
{
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO
};

void logger_init();

void logger_free();

void log_msg(enum LOG_LEVEL logLevel, const char* format, ...);

#endif
