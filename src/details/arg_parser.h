#ifndef RGCP_MIDDLEWARE_ARG_PARSER
#define RGCP_MIDDLEWARE_ARG_PARSER

#include <stdint.h>
#include <time.h>

extern uint8_t g_bDisplayHelp;
extern uint8_t g_bPortIsSet;
extern uint8_t g_bHeartbeatTimeoutIsSet;
extern uint8_t g_bGroupTimeoutIsSet;
extern uint16_t g_middlewarePort;
extern time_t   g_heartbeatTimeout;
extern time_t   g_groupTimeout;

int parse_middleware_arguments(int argc, char** argv);

#endif
