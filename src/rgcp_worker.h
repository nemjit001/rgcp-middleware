#ifndef RGCP_WORKER_H
#define RGCP_WORKER_H

struct rgcp_worker_state
{
    int serverfd;
    int clientfd;
};

__attribute__((noreturn)) void worker_start(int serverfd, int clientfd);

#endif // RGCP_WORKER_H
