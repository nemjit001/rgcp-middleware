#include "arg_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

uint8_t g_bDisplayHelp = 0;
uint8_t g_bPortIsSet = 0;
uint8_t g_bHeartbeatTimeoutIsSet = 0;
uint8_t g_bGroupTimeoutIsSet = 0;
uint16_t g_middlewarePort = 0;
time_t   g_heartbeatTimeout = 0;
time_t   g_groupTimeout = 0;

#define RGCP_MIDDLEWARE_HELP_MSG \
"\
usage: rgcp_middleware [options]\n\
This middleware service allows RGCP sockets to interface with RGCP groups.\n\
\n\
Available options, with defaults in [ ]:\n\
\t-p, --port\t\tSet the port on which the middleware listens for\n\
\t\t\t\tconnections, ranges 1~65535. [8000]\n\
\t-g, --group-timeout\tSet the time it takes for an inactive group to\n\
\t\t\t\texpire in seconds. [60]\n\
\t-b, --heartbeat-timeout\tSet the expected period for heartbeat messages received\n\
\t\t\t\tfrom clients in seconds. [5]\n\
\t-h, --help\t\tDisplay this help message.\n\
\n\
For contact info, issues, bug reports, feedback, etc., go to: www.github.com/nemjit001/rgcp-middleware\n\
"

static struct option g_longOptions[] = {
    { "help",                   no_argument,        NULL, 0 },
    { "port",                   required_argument,  NULL, 1 },
    { "heartbeat-timeout",      required_argument,  NULL, 2 },
    { "group-timeout",          required_argument,  NULL, 3 }
};

void display_help()
{
    printf("%s\n", RGCP_MIDDLEWARE_HELP_MSG);
}

int get_long_from_optarg(long* pOut)
{
    if (!pOut)
        return -1;

    errno = 0;
    char* argStart = optarg;
    char* argEnd = NULL;

    *pOut = strtol(argStart, &argEnd, 10);

    if (errno != 0 || argStart == argEnd)
        return -1;

    return 0;
}

int parse_middleware_arguments(int argc, char** argv)
{
    for(;;)
    {
        int longOptionIdx = 0;
        int optRes = getopt_long(argc, argv, "hp:b:g:", g_longOptions, &longOptionIdx);

        if (optRes < 0 || optRes == (int)('?'))
            break;
        
        switch (optRes)
        {
        case 0:
        case 'h':
        {
            // Early return for displaying help.
            // Other arguments don't matter because the program exits once the help message has been displayed.

            g_bDisplayHelp = 1;
            display_help();
            return 0;
        }

        case 1:
        case 'p':
        {
            long setPort = -1;

            if (get_long_from_optarg(&setPort) < 0)
                return -1;
            
            if (setPort < 0 || setPort > 65535)
                return -1;

            g_middlewarePort = (uint16_t)setPort;
            g_bPortIsSet = 1;
            break;
        }

        case 2:
        case 'b':
        {
            if (get_long_from_optarg(&g_heartbeatTimeout) < 0)
                return -1;
            
            g_bHeartbeatTimeoutIsSet = 1;
            break;
        }

        case 3:
        case 'g':
        {
            if (get_long_from_optarg(&g_groupTimeout) < 0)
                return -1;
            
            g_bGroupTimeoutIsSet = 1;
            break;
        }

        default:
            break;
        }
    }

    if (optind < argc)
        return -1;

    return 0;
}
