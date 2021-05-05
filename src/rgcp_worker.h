#ifndef RGCP_WORKER_H
#define RGCP_WORKER_H

__attribute__((noreturn)) void worker_start(int serverfd, int clientfd, struct sockaddr_in peer_addr, socklen_t peer_addr_len);

#endif // RGCP_WORKER_H
