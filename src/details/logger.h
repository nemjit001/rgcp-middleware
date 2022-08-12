#ifndef LOGGER
#define LOGGER

#include <stdarg.h>
#include <stdio.h>

enum LOG_LEVEL
{
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_ERROR = 4
};

void logger_init();

void logger_free();

void log_msg(enum LOG_LEVEL logLevel, const char* format, ...);

#endif
