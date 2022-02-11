#ifndef RGCP_GROUP
#define RGCP_GROUP

#include "linked_list.h"

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

struct rgcp_group_child
{
    struct list_entry m_listEntry;
    void* pChild;
};

struct rgcp_group
{
    struct list_entry m_listEntry;
    struct list_entry m_pGroupChildListHead;

    struct
    {
        uint32_t m_groupHash;
        const char* m_pGroupName;
        size_t m_nameLength;
    } m_groupNameInfo;

    size_t m_childCount;
};

void rgcp_group_init(struct rgcp_group* pGroup, const char* pGroupName, size_t nameLength);

void rgcp_group_free(struct rgcp_group group);

int rgcp_group_empty(struct rgcp_group group);

int rgcp_group_register_child(struct rgcp_group* pGroup, void* pChild);

void rgcp_group_delete_child(struct rgcp_group* pGroup, struct rgcp_group_child* pGroupChild);


#endif
