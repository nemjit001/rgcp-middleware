#include "rgcp_group.h"

#include <assert.h>
#include <string.h>

#include "crc32.h"

void rgcp_group_init(struct rgcp_group* pGroup, const char* pGroupName, size_t nameLength)
{
    assert(pGroup);
    assert(nameLength == strlen(pGroupName));

    list_init(&pGroup->m_pGroupChildListHead);
    pGroup->m_childCount = 0;
    pGroup->m_groupNameInfo.m_pGroupName = calloc(nameLength + 1, sizeof(char));

    assert(pGroup->m_groupNameInfo.m_pGroupName);
    memcpy((void*)pGroup->m_groupNameInfo.m_pGroupName, (void*)pGroupName, nameLength);

    pGroup->m_groupNameInfo.m_nameLength = nameLength;
    pGroup->m_groupNameInfo.m_groupHash = CRC32_STR_DYNAMIC(pGroupName, nameLength); 
}

void rgcp_group_free(struct rgcp_group group)
{
    free((void*)group.m_groupNameInfo.m_pGroupName);
}

int rgcp_group_empty(struct rgcp_group group)
{
    return group.m_childCount == 0;
}

int rgcp_group_register_child(struct rgcp_group* pGroup, void* pChild)
{
    struct rgcp_group_child* pNew = malloc(sizeof(struct rgcp_group_child));
    assert(pNew);

    if (!pNew)
        return -1;

    pNew->pChild = pChild;
    list_add_tail(&pNew->m_listEntry, &pGroup->m_pGroupChildListHead);
    pGroup->m_childCount++;

    return 0;
}

void rgcp_group_delete_child(struct rgcp_group* pGroup, struct rgcp_group_child* pGroupChild)
{
    list_del(&pGroupChild->m_listEntry);
    free(pGroupChild);
    pGroup->m_childCount--;
}
