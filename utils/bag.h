#ifndef _UTILS_QUEUE_H
#define _UTILS_QUEUE_H

#include <stdbool.h>

struct _Bag;
typedef struct _Bag Bag;

/** Create a new Bag. */
Bag * Bag_new(bool thread_safe);

/** Free the Bag. Note: the bag must be empty or memory will be leaked. */
void Bag_free(Bag * bag);

/**
	Try to add data to the bag. This can fail if there isn't enough memory.

	@return Whether or not the add was successful.
*/
bool Bag_add(Bag * bag, void * data);

/**
	Foreach macros to help with iterating over a bag. Caveats:
		* You MUST call Bag_foreach_cleanup in every case that control can pass out of the Bag_foreach loop.
		* You MUST NOT use any data created by Bag_foreach after calling Bag_foreach_cleanup.
		* You MUST NOT use the bag for any other purposes between Bag_foreach and Bag_foreach_cleanup.

	Example that prints the elements of a bag (my_bag) that contains C strings:

	printf("my_bag:\n");
	Bag_foreach(char *, str, my_bag)
	{
		if (str == NULL || str[0] == 'a')
		{
			Bag_foreach_cleanup(my_bag);
			printf("  my_bag has something ugly!\n");
			exit(EXIT_FAILURE);
		}

		if (str[0] == '\0')
			continue;

		printf("  %s", str);
	}
	Bag_foreach_cleanup(my_bag);
*/
#define Bag_foreach(type, var, bag) \
	for ( \
		Bag * _Bag_foreach_bag = (bag), \
			_Bag_lock(_Bag_foreach_bag), \
			void * _Bag_foreach_iterator = _Bag_begin(_Bag_foreach_bag), \
			type var = (type)_Bag_iterator_get(_Bag_foreach_bag, _Bag_foreach_iterator); \
		_Bag_foreach_iterator != NULL; \
		_Bag_iterator_next(_Bag_foreach_bag, _Bag_foreach_iterator), \
			var = (type)_Bag_iterator_get(_Bag_foreach_bag, _Bag_foreach_iterator))
#define Bag_foreach_cleanup(bag) \
	do { \
		_Bag_unlock(bag); \
	} while (false)

/*
 * NOTE: DO NOT CALL THE BELOW FUNCTIONS DIRECTLY. Use Bag_foreach above instead.
 */
void _Bag_lock(Bag * bag);
void _Bag_unlock(Bag * bag);
void * _Bag_begin(Bag * bag);
void * _Bag_iterator_get(Bag * bag, void * iterator);
_Bag_iterator_next(Bag * bag, void * iterator);

#endif
