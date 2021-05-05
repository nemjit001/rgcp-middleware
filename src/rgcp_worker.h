#ifndef RGCP_WORKER_H
#define RGCP_WORKER_H

__attribute__((noreturn)) void worker_start(int serverfd, int clientfd);

#endif // RGCP_WORKER_H
