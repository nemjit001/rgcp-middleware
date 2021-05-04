#include <stdio.h>

#include "rgcp_worker.h"

void worker_start(int serverfd, int clientfd)
{
    printf("\t[RGCP worker (%d)] starting worker\n", serverfd, clientfd);

    for(;;);
}
