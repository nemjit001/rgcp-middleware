#include "logger.h"

#include <pthread.h>

static pthread_mutex_t g_loggingMtx;

void logger_init()
{
    pthread_mutex_init(&g_loggingMtx, NULL);
}

void logger_free()
{
    pthread_mutex_destroy(&g_loggingMtx);
}

void log_msg(enum LOG_LEVEL logLevel, const char* format, ...)
{
#ifdef NDEBUG
    if (logLevel == LOG_LEVEL_DEBUG)
        return;
#endif

    pthread_mutex_lock(&g_loggingMtx);

    va_list args;
    va_start(args, format);

    switch(logLevel)
    {
    case LOG_LEVEL_DEBUG:
        printf("[DEBUG]");
        break;
    case LOG_LEVEL_INFO:
        printf("[INFO]");
        break;
    case LOG_LEVEL_ERROR:
        printf("[ERROR]");
    default:
        break;
    }

    vprintf(format, args);

    va_end(args);

    pthread_mutex_unlock(&g_loggingMtx);
}
