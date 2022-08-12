#ifndef LINKED_LIST
#define LINKED_LIST

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

struct list_entry
{
    struct list_entry *m_pPrev, *m_pNext;
};

#define LIST_HEAD(name) static struct list_entry name = { &(name), &(name) }

static inline void list_init(struct list_entry* pHead)
{
    assert(pHead);

    pHead->m_pPrev = pHead->m_pNext = pHead;
}

static inline void list_add_front(struct list_entry *pNew, struct list_entry *pHead)
{
    pHead->m_pNext->m_pPrev = pNew;
    pNew->m_pNext = pHead->m_pNext;
    pNew->m_pPrev = pHead;
    pHead->m_pNext = pNew;
}

static inline void list_add_tail(struct list_entry *pNew, struct list_entry *pHead)
{
    pHead->m_pPrev->m_pNext = pNew;
    pNew->m_pPrev = pHead->m_pPrev;
    pNew->m_pNext = pHead;
    pHead->m_pPrev = pNew; 
}

static inline void list_del(struct list_entry *pElem)
{
    struct list_entry *pPrev = pElem->m_pPrev;
    struct list_entry *pNext = pElem->m_pNext;
    
    pPrev->m_pNext = pNext;
    pNext->m_pPrev = pPrev;
}

static inline int list_empty(struct list_entry* pHead)
{
    return (pHead->m_pNext == pHead);
}

#define LIST_ENTRY(ptr, type, member) ((type*)((uint8_t*)(ptr) - offsetof(type, member)))

#define LIST_FIRST_ENTRY(ptr, type, member) LIST_ENTRY(ptr->m_pNext, type, member)

#define LIST_FOR_EACH(pCurrent, pNext, pHead) for (pCurrent = (pHead)->m_pNext, pNext = pCurrent->m_pNext; pCurrent != (pHead); pCurrent = pNext, pNext = pCurrent->m_pNext)

#endif
