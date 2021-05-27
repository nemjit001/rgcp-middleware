#include "rgcp_workerapi.h"

int workerapi_send(int fd, struct rgcp_workerapi_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    ssize_t bytes_sent = write(fd, (uint8_t *)packet, packet->packet_len);

    if (bytes_sent <= 0)
        return -1;

    return bytes_sent;
}

int workerapi_recv(int fd, struct rgcp_workerapi_packet **packet)
{
    assert(fd >= 0);
    assert(*packet == NULL);

    uint8_t size_buffer[sizeof(uint32_t)];
    int res1 = read(fd, size_buffer, sizeof(uint32_t));

    // If error remote client has exited unexpectedly or closed socket incorrectly
    if (res1 < 0)
        return -1;

    // client closed normally
    if (res1 == 0)
        return 0;

    uint32_t packet_length = 0;

    for (size_t i = 0; i < sizeof(uint32_t); i++)
        packet_length += (uint8_t)(size_buffer[i] >> (sizeof(uint8_t) - 1 - i));

    // erronous packet length received, probably due to client crash
    if (packet_length == 0)
        return -1;

    uint8_t data_buffer[packet_length - sizeof(uint32_t)];
    int res2 = read(fd, data_buffer, packet_length - sizeof(uint32_t));

    // second recv call empty check
    if (res2 < 0)
        return -1;

    uint8_t packet_buffer[packet_length];

    // copying over to relevant pointer offsets
    memcpy(packet_buffer, size_buffer, sizeof(uint32_t));
    memcpy(packet_buffer + sizeof(uint32_t), data_buffer, packet_length - sizeof(uint32_t));

    *packet = calloc(packet_length, 1);
    memcpy(*packet, packet_buffer, packet_length);

    return res1 + res2;
}
