#ifndef RGCP_MW_GROUP_H
#define RGCP_MW_GROUP_H

#include "linked_list.h"

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <rgcp/rgcp.h>

struct rgcp_middleware_group_child
{
    struct list_entry m_listEntry;
    void* pChild;
};

struct rgcp_middleware_group
{
    struct list_entry m_listEntry;
    struct list_entry m_groupChildListHead;

    rgcp_group_info_t m_groupNameInfo;

    size_t m_childCount;
    time_t m_lastActivityTimestamp;
};

void rgcp_middleware_group_init(struct rgcp_middleware_group* pGroup, const char* pGroupName, size_t nameLength);

void rgcp_middleware_group_free(struct rgcp_middleware_group* pGroup);

int rgcp_middleware_group_empty(struct rgcp_middleware_group group);

int rgcp_middleware_group_register_child(struct rgcp_middleware_group* pGroup, void* pChild);

void rgcp_middleware_group_delete_child(struct rgcp_middleware_group* pGroup, struct rgcp_middleware_group_child* pGroupChild);

#endif
