#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bag.h"

#ifndef DEBUG
#define NDEBUG
#endif
#include <assert.h>


#ifdef DEBUG
	#define BAG_INVARIANTS(bag) \
		do { \
			if (bag != NULL) { \
				assert(bag->entries != NULL); \
				assert(bag->used != NULL); \
				assert(bag->size <= bag->allocated_size); \
			} \
		} while (false)
#else
	#define BAG_INVARIANTS(bag) do {} while (false)
#endif


// how many entries to allocate space for initially
#define BAG_ALLOC_START 16

typedef uint_fast8_t bitmap_entry_t;

struct _Bag {
	bool thread_safe; // NOTE: this must not be changed once Bag_new returns
	void ** entries; // sparse array of pointers to entries
	bitmap_entry_t * used; // bitmap of which pointers in entries are filled in
	bool last_realloc_automatic; // whether the last realloc was automatic or manual (Bag_reserve)
	size_t allocated_size;
	size_t size;
	pthread_rwlock_t lock;
};


inline static size_t bitmap_size(size_t num_entries)
{
	return (num_entries / (8*sizeof(bitmap_entry_t))) +
		((num_entries % (8*sizeof(bitmap_entry_t))) == 0 ? 0 : 1);
}

inline static size_t _bitmap_index(size_t index)
{
	return index / (8*sizeof(bitmap_entry_t));
}

inline static bitmap_entry_t _bitmap_mask(size_t index)
{
	return (1 << (index % (8*sizeof(bitmap_entry_t))));
}

inline static bool bitmap_get(bitmap_entry_t * bitmap, size_t index)
{
	assert(bitmap != NULL);
	return bitmap[_bitmap_index(index)] & _bitmap_mask(index);
}

inline static void bitmap_set(bitmap_entry_t * bitmap, size_t index)
{
	assert(bitmap != NULL);
	bitmap[_bitmap_index(index)] |= _bitmap_mask(index);
}

inline static void bitmap_clear(bitmap_entry_t * bitmap, size_t index)
{
	assert(bitmap != NULL);
	bitmap[_bitmap_index(index)] &= ~_bitmap_mask(index);
}


Bag * Bag_new(bool thread_safe)
{
	Bag * bag = calloc(1, sizeof(Bag));
	if (bag == NULL)
		return NULL;

	bag->thread_safe = thread_safe;

	bag->entries = calloc(BAG_ALLOC_START, sizeof(void *));
	if (bag->entries == NULL)
	{
		free(bag);
		return NULL;
	}

	bag->used = calloc(bitmap_size(BAG_ALLOC_START), sizeof(bitmap_entry_t));
	if (bag->used == NULL)
	{
		free(bag->entries);
		free(bag);
		return NULL;
	}

	bag->last_realloc_automatic = true;
	bag->allocated_size = BAG_ALLOC_START;
	bag->size = 0;

	if (bag->thread_safe)
	{
		if (pthread_rwlock_init(&bag->lock, NULL) != 0)
		{
			free(bag->used);
			free(bag->entries);
			free(bag);
			return NULL;
		}
	}

	BAG_INVARIANTS(bag);

	return bag;
}

void Bag_free(Bag * bag)
{
	if (bag == NULL)
		return;

	BAG_INVARIANTS(bag);

	assert(bag->size == 0);

	free(bag->entries);

	free(bag->used);

	if (bag->thread_safe)
	{
		// NOTE: return code is ignored, but there's not much that can be done anyway
		pthread_rwlock_destroy(&bag->lock);
	}

	free(bag);
}

static bool Bag_rdlock(Bag * bag)
{
	assert(bag != NULL);

	if (bag->thread_safe)
		if (pthread_rwlock_rdlock(&bag->lock) != 0)
			return false;

	BAG_INVARIANTS(bag);

	return true;
}

static bool Bag_wrlock(Bag * bag)
{
	assert(bag != NULL);

	if (bag->thread_safe)
		if (pthread_rwlock_wrlock(&bag->lock) != 0)
			return false;

	BAG_INVARIANTS(bag);

	return true;
}

static bool Bag_unlock(Bag * bag)
{
	assert(bag != NULL);

	BAG_INVARIANTS(bag);

	if (bag->thread_safe)
		if (pthread_rwlock_unlock(&bag->lock) != 0)
			return false;

	return true;
}

size_t Bag_size(Bag * bag)
{
	size_t size;

	assert(bag != NULL);

	// See comments in queue.c:Queue_size() for why the return values of
	// lock() and unlock() are ignored.

	Bag_rdlock(bag);

	size = bag->size;

	Bag_unlock(bag);

	return size;
}

/**
	Reallocate the bag to support num_entries entries.

	@param bag		Bag to operate on.
	@param num_entries	Number of entries to support after reallocating.
	@param automatic	Whether or not this realloc was explitly requested by the user.
	@param track_index	A pointer to an index to a entry. If the entry is moved, the index is updated. Can be NULL.

	NOTE: you MUST hold the lock for writing when calling this.
*/
static bool Bag_realloc(Bag * bag, size_t num_entries, bool automatic, size_t * track_index)
{
	assert(bag != NULL);

	BAG_INVARIANTS(bag);

	assert(num_entries >= bag->size);

	if (!bag->last_realloc_automatic && num_entries <= bag->allocated_size)
	{
		BAG_INVARIANTS(bag);
		return true; // don't clobber manual calls to bag_reserve
	}

	if (num_entries < bag->allocated_size / 4 && bag->allocated_size > BAG_ALLOC_START)
	{
		size_t shrink_to = bag->allocated_size / 2;
		if (shrink_to < BAG_ALLOC_START) shrink_to = BAG_ALLOC_START;

		assert(shrink_to < bag->allocated_size);
		assert(shrink_to >= BAG_ALLOC_START);
		assert(shrink_to > num_entries);
		assert(shrink_to > bag->size);

		void ** new_entries = malloc(shrink_to * sizeof(void*));
		if (new_entries == NULL)
		{
			BAG_INVARIANTS(bag);
			return false;
		}

		bitmap_entry_t * new_used = calloc(bitmap_size(shrink_to), sizeof(bitmap_entry_t));
		if (new_used == NULL)
		{
			free(new_entries);
			BAG_INVARIANTS(bag);
			return false;
		}

		size_t new_index, index;
		for (new_index = 0, index = 0; index < bag->allocated_size; ++index)
		{
			if (bitmap_get(bag->used, index))
			{
				if (track_index != NULL && *track_index == index)
					*track_index = new_index;

				new_entries[new_index] = bag->entries[index];
				bitmap_set(new_used, new_index);
				++new_index;
			}
		}

		free(bag->entries);
		free(bag->used);
		bag->entries = new_entries;
		bag->used = new_used;
		bag->last_realloc_automatic = automatic;
		bag->allocated_size = shrink_to;

		BAG_INVARIANTS(bag);
		return true;
	}
	else if (num_entries > bag->allocated_size)
	{
		size_t grow_to = bag->allocated_size;
		while (grow_to < num_entries) grow_to *= 2;

		assert(grow_to > bag->allocated_size);
		assert(grow_to > BAG_ALLOC_START);
		assert(grow_to >= num_entries);
		assert(grow_to > bag->size);

		void ** new_entries = realloc(bag->entries, grow_to * sizeof(void*));
		if (new_entries == NULL)
		{
			BAG_INVARIANTS(bag);
			return false;
		}
		else
		{
			bag->entries = new_entries;
		}

		assert(bitmap_size(grow_to) >= bitmap_size(bag->allocated_size));
		if (bitmap_size(grow_to) > bitmap_size(bag->allocated_size))
		{
			bitmap_entry_t * new_used = realloc(bag->used, bitmap_size(grow_to) * sizeof(bitmap_entry_t));
			if (new_used == NULL)
			{
				BAG_INVARIANTS(bag);
				return false;
			}
			else
			{
				bag->used = new_used;
				memset((void *)(bag->used + bitmap_size(bag->allocated_size)),
					0,
					sizeof(bitmap_entry_t) * (bitmap_size(grow_to) - bitmap_size(bag->allocated_size)));
			}
		}

		bag->last_realloc_automatic = automatic;
		bag->allocated_size = grow_to;

		BAG_INVARIANTS(bag);
		return true;
	}

	BAG_INVARIANTS(bag);
	return true;
}

bool Bag_reserve(Bag * bag, size_t num_entries)
{
	assert(bag != NULL);

	if (!Bag_wrlock(bag))
		return false;

	if (num_entries <= bag->allocated_size)
	{
		return Bag_unlock(bag);
	}

	bool ret = Bag_realloc(bag, num_entries, false, NULL);

	return Bag_unlock(bag) && ret; // order of the operands to '&&' matters here
}

bool Bag_add(Bag * bag, void * data)
{
	assert(bag != NULL);

	if (!Bag_wrlock(bag))
		return false;

	if (!Bag_realloc(bag, bag->size + 1, true, NULL))
	{
		// return value of unlock is ignored because there's nothing good to do with it
		Bag_unlock(bag);
		return false;
	}

	size_t i;
	for (i = 0; i < bag->allocated_size; ++i)
	{
		if (!bitmap_get(bag->used, i))
		{
			bitmap_set(bag->used, i);
			bag->entries[i] = data;
			++bag->size;
			return Bag_unlock(bag);
		}
	}

	// Execution should never reach here because Bag_realloc above
	// (if successful) ensures there are unset bits in bag->used.
	Bag_unlock(bag);
	assert(false);
	return false;
}


bool Bag_start_iteration(Bag * bag) { return Bag_wrlock(bag); }
bool Bag_start_const_iteration(Bag * bag) { return Bag_rdlock(bag); }
bool Bag_stop_iteration(Bag * bag) { return Bag_unlock(bag); }
bool Bag_stop_const_iteration(Bag * bag) { return Bag_unlock(bag); }


#define BAG_BEGIN_BODY \
	assert(bag != NULL); \
	\
	BAG_INVARIANTS(bag); \
	\
	size_t index; \
	for (index = 0; index < bag->allocated_size; ++index) \
	{ \
		if (bitmap_get(bag->used, index)) \
			return bag->entries + index; \
	} \
	return NULL;

Bag_iterator Bag_begin(Bag * bag) { BAG_BEGIN_BODY }
Bag_const_iterator Bag_const_begin(Bag * bag) { BAG_BEGIN_BODY }

#undef BAG_BEGIN_BODY


static inline size_t _Bag_iterator_to_index(Bag const * bag, Bag_const_iterator iterator)
{
	assert(bag != NULL);
	assert(iterator != NULL);

	assert(iterator >= (Bag_const_iterator)bag->entries);
	assert(iterator < (Bag_const_iterator)(bag->entries + bag->allocated_size));

	size_t index = (void const * const *)iterator - (void const * const *)bag->entries;

	assert(index < bag->allocated_size);

	return index;
}


#define BAG_ITERATOR_NEXT_BODY \
	assert(bag != NULL); \
	\
	BAG_INVARIANTS(bag); \
	\
	if (iterator == NULL) \
		return NULL; \
	\
	size_t index = _Bag_iterator_to_index(bag, iterator); \
	\
	assert(bitmap_get(bag->used, index)); \
	\
	while (++index < bag->allocated_size) \
	{ \
		if (bitmap_get(bag->used, index)) \
			return bag->entries + index; \
	} \
	return NULL;

Bag_iterator Bag_iterator_next(Bag * bag, Bag_iterator iterator) { BAG_ITERATOR_NEXT_BODY }
Bag_const_iterator Bag_const_iterator_next(Bag * bag, Bag_const_iterator iterator) { BAG_ITERATOR_NEXT_BODY }

#undef BAG_ITERATOR_NEXT_BODY


#define BAG_GET_BODY(iterator_type, return_type) \
	assert(bag != NULL); \
	\
	BAG_INVARIANTS(bag); \
	\
	assert(iterator != NULL); \
	\
	assert(iterator >= (iterator_type)bag->entries); \
	assert(iterator < (iterator_type)(bag->entries + bag->allocated_size)); \
	\
	assert(bitmap_get(bag->used, (void const * const *)iterator - (void const * const *)bag->entries)); \
	\
	return *((return_type *)iterator);

void * Bag_get(Bag * bag, Bag_iterator iterator) { BAG_GET_BODY(Bag_iterator, void *) }
const void * Bag_const_get(Bag const * bag, Bag_const_iterator iterator) { BAG_GET_BODY(Bag_const_iterator, const void *) }

#undef BAG_GET_BODY


Bag_iterator Bag_erase(Bag * bag, Bag_iterator iterator)
{
	assert(bag != NULL);

	BAG_INVARIANTS(bag);

	if (iterator == NULL)
		return NULL;

	size_t index = _Bag_iterator_to_index(bag, iterator);

	assert(bitmap_get(bag->used, index));

	#ifdef DEBUG
	bag->entries[index] = NULL;
	#endif

	bitmap_clear(bag->used, index);

	--bag->size;

	for (; index < bag->allocated_size; ++index)
		if (bitmap_get(bag->used, index))
			break;

	// The return value of Bag_realloc is ignored because even if
	// the shrink fails, the results of Bag_erase are still correct.
	if (index < bag->allocated_size)
	{
		Bag_realloc(bag, bag->size, true, &index);
		return bag->entries + index;
	}
	else
	{
		Bag_realloc(bag, bag->size, true, NULL);
		return NULL;
	}
}
