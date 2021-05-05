#include "rgcp_workerapi.h"

int workerapi_send(int fd, struct rgcp_workerapi_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    // TODO: check if this OK, depends on packet struct
    ssize_t bytes_sent = write(fd, (uint8_t *)packet, sizeof(*packet));

    if (bytes_sent <= 0)
        return -1;

    return bytes_sent;
}

int workerapi_recv(int fd, struct rgcp_workerapi_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    // FIXME: change 2048 -> max packet size, only know when packet struct fully defined
    uint8_t buffer[2048];
    ssize_t bytes_received = read(fd, buffer, sizeof(buffer));

    // If remote client has exited or closed socket
    if (bytes_received < 0)
    {
        perror("Read failed");
        return -1;
    }

    if (bytes_received == 0)
        return 0;

    memcpy(packet, buffer, bytes_received);

    return bytes_received;
}
