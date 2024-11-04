#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <stddef.h>

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * This is a cut-down copy of libnfnetlink/include/linux_list.h which is itself
 * an old snapshot of linux/include/linux/list.h.
 * This file only contains what we use.
 *
 * 2024-01-27 12:45:41 +1100 duncan_roe@optusnet.com.au
 * LIST_POISONx doesn't really work for user space - just use NULL
 *
 * 2024-01-27 18:16:51 +1100 duncan_roe@optusnet.com.au
 * I can't see how the prefetch() calls do any good so remove them
 * and #define of prefetch
 *
 * 2024-01-27 18:53:46 +1100 duncan_roe@optusnet.com.au
 * Take a few doxygen comment improvements from 6.6 Linux source
 */

/**
 * \defgroup List Circular doubly linked list implementation
 *
 * Unlike file units (which are re-used), network interface indicies
 * increase monotonically as they are brought up and down.
 *
 * To keep memory usage predictable as indices increase,
 * the nlif_* functions keep their data in a circular list
 * (in fact a number of lists, to minimise search times).
 *
 * \manonly
.SH SYNOPSIS
.nf
\fB
#include <libnetfilter_queue/libnetfilter_queue.h>
\endmanonly
 * @{
 */


/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * \param ptr:	the pointer to the member.
 * \param type:	the type of the container struct this is embedded in.
 * \param member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	typeof(((type *)0)->member) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

/*
 * Circular doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

/**
 * \struct list_head
 * Link to adjacent members of the circular list
 * \note Each member of a list must start with this structure
 * (containing structures OK)
 * \var list_head::next
 * pointer to the next list member
 * \var list_head::prev
 * pointer to the previous list member
 */
struct list_head {
	struct list_head *next, *prev;
};

/**
 * INIT_LIST_HEAD - Initialise first member of a new list
 * \param ptr the &struct list_head pointer.
 */
#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add - add a new entry
 * \param new: new entry to be added
 * \param head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * \param entry: the element to delete from the list.
 * \note
 * list_empty() on **entry** does not return true after this, **entry** is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

/**
 * list_empty - tests whether a list is empty
 * \param head: the list to test.
 * \return 1 if list is empty, 0 otherwise
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_entry - get the struct for this entry
 * \param ptr:	the &struct list_head pointer.
 * \param type:	the type of the struct this is embedded in.
 * \param member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_for_each_entry	-	iterate over list of given type
 * \param pos:	the type * to use as a loop cursor.
 * \param head:	the head for your list.
 * \param member:	the name of the list_head within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))	\

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * \param pos:	the type * to use as a loop cursor.
 * \param n:		another type * to use as temporary storage
 * \param head:	the head for your list.
 * \param member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * @}
 */

#endif
