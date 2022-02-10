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

    assert(pthread_mutex_init(&pGroup->m_groupMtx, NULL) < 0);        
}

void rgcp_group_free(struct rgcp_group group)
{
    pthread_mutex_destroy(&group.m_groupMtx);
    free((void*)group.m_groupNameInfo.m_pGroupName);
}
