#include "rgcp_middleware_group.h"

#include <assert.h>
#include <string.h>

#include "crc32.h"

void rgcp_middleware_group_init(struct rgcp_middleware_group* pGroup, const char* pGroupName, size_t nameLength)
{
    assert(pGroup);
    assert(nameLength == strlen(pGroupName));

    list_init(&pGroup->m_pGroupChildListHead);
    pGroup->m_childCount = 0;
    pGroup->m_groupNameInfo.m_pGroupName = calloc(nameLength + 1, sizeof(char));

    assert(pGroup->m_groupNameInfo.m_pGroupName);
    memcpy((void*)pGroup->m_groupNameInfo.m_pGroupName, (void*)pGroupName, nameLength);

    pGroup->m_groupNameInfo.m_groupNameLength = nameLength;
    pGroup->m_groupNameInfo.m_groupNameHash = CRC32_STR_DYNAMIC(pGroupName, nameLength); 
}

void rgcp_middleware_group_free(struct rgcp_middleware_group group)
{
    free((void*)group.m_groupNameInfo.m_pGroupName);
}

int rgcp_middleware_group_empty(struct rgcp_middleware_group group)
{
    return group.m_childCount == 0;
}

int rgcp_middleware_group_register_child(struct rgcp_middleware_group* pGroup, void* pChild)
{
    struct rgcp_middleware_group_child* pNew = malloc(sizeof(struct rgcp_middleware_group_child));
    assert(pNew);

    if (!pNew)
        return -1;

    pNew->pChild = pChild;
    list_add_tail(&pNew->m_listEntry, &pGroup->m_pGroupChildListHead);
    pGroup->m_childCount++;

    return 0;
}

void rgcp_middleware_group_delete_child(struct rgcp_middleware_group* pGroup, struct rgcp_middleware_group_child* pGroupChild)
{
    list_del(&pGroupChild->m_listEntry);
    free(pGroupChild);
    pGroup->m_childCount--;
}
