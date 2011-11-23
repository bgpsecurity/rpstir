#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include "bag.h"
#include "unittest.h"

bool empty_test(Bag * bag)
{
	size_t size = 0;
	Bag_const_iterator it;

	assert(bag != NULL);
	assert(Bag_size(bag) == 0);

	TEST_BOOL(Bag_start_const_iteration(bag), true);
	for (it = Bag_const_begin(bag);
		it != Bag_const_end(bag);
		it = Bag_const_iterator_next(bag, it))
	{
		++size;
	}
	TEST_BOOL(Bag_stop_const_iteration(bag), true);

	TEST(size_t, "%zd", size, ==, 0);

	TEST(size_t, "%zd", Bag_size(bag), ==, 0);

	return true;
}

bool correctness_test(Bag * bag)
{
	ssize_t i;
	uint64_t found; // bitmap
	Bag_const_iterator const_it;
	Bag_iterator it;
	const void * data;

	assert(bag != NULL);
	assert(Bag_size(bag) == 0);

	for (i = 0; i < 64; ++i)
	{
		TEST(ssize_t, "%zd", (ssize_t)Bag_size(bag), ==, i);
		TEST_BOOL(Bag_add(bag, (void*)i), true);
		TEST(ssize_t, "%zd", (ssize_t)Bag_size(bag), ==, i + 1);
	}

	#define CONTENTS_TEST(start_iteration, stop_iteration, iterator, begin, end, next, get) \
		do { \
			found = 0; \
			\
			TEST_BOOL(start_iteration(bag), true); \
			for (iterator = begin(bag); iterator != end(bag); iterator = next(bag, iterator)) \
			{ \
				data = get(bag, iterator); \
				\
				TEST(int, "%d", (int)data, >=, 0); \
				TEST(int, "%d", (int)data, <, 64); \
				\
				TEST_BOOL(found & ((uint64_t)1 << (int)data), false); \
				\
				found |= (uint64_t)1 << (int)data; \
			} \
			TEST_BOOL(stop_iteration(bag), true); \
			\
			TEST(uint64_t, "%" PRIu64, found, ==, UINT64_MAX); \
		} while (false)

	CONTENTS_TEST(Bag_start_const_iteration, Bag_stop_const_iteration,
		const_it, Bag_const_begin, Bag_const_end, Bag_const_iterator_next, Bag_const_get);

	CONTENTS_TEST(Bag_start_iteration, Bag_stop_iteration, it,
		Bag_begin, Bag_end, Bag_iterator_next, Bag_get);

	CONTENTS_TEST(Bag_start_iteration, Bag_stop_iteration, it,
		Bag_begin, Bag_end, Bag_erase, Bag_get);

	#undef CONTENTS_TEST

	TEST(size_t, "%zd", Bag_size(bag), ==, 0);

	return true;
}

bool stress_test(Bag * bag, size_t num_entries)
{
	ssize_t i;
	Bag_iterator it;

	assert(bag != NULL);
	assert(Bag_size(bag) == 0);

	#define ADD_ENTRIES \
		do { \
			for (i = 0; i < (ssize_t)num_entries; ++i) \
			{ \
				TEST(ssize_t, "%zd", (ssize_t)Bag_size(bag), ==, i); \
				TEST_BOOL(Bag_add(bag, NULL), true); \
				TEST(ssize_t, "%zd", (ssize_t)Bag_size(bag), ==, i + 1); \
			} \
			\
			TEST(size_t, "%zd", Bag_size(bag), ==, num_entries); \
		} while (false)

	#define CLEAR_ENTRIES \
		do { \
			TEST_BOOL(Bag_start_iteration(bag), true); \
			it = Bag_begin(bag); \
			while (it != Bag_end(bag)) \
				it = Bag_erase(bag, it); \
			TEST_BOOL(Bag_stop_iteration(bag), true); \
			\
			TEST(size_t, "%zd", Bag_size(bag), ==, 0); \
		} while (false)

	ADD_ENTRIES;

	CLEAR_ENTRIES;

	TEST_BOOL(Bag_reserve(bag, num_entries / 3), true);

	ADD_ENTRIES;

	CLEAR_ENTRIES;

	TEST_BOOL(Bag_reserve(bag, num_entries), true);

	ADD_ENTRIES;

	CLEAR_ENTRIES;

	#undef ADD_ENTRIES
	#undef CLEAR_ENTRIES

	return true;
}

bool run_test(Bag * bag)
{
	TEST(void *, "%p", (void *)bag, !=, NULL);

	if (!empty_test(bag)) return false;
	if (!correctness_test(bag)) return false;
	if (!empty_test(bag)) return false;
	if (!stress_test(bag, 5000)) return false;
	if (!empty_test(bag)) return false;
	if (!correctness_test(bag)) return false;
	if (!empty_test(bag)) return false;
	if (!stress_test(bag, 1000)) return false;
	if (!empty_test(bag)) return false;
	if (!correctness_test(bag)) return false;
	if (!empty_test(bag)) return false;

	Bag_free(bag);

	return true;
}

int main(void)
{
	if (!run_test(Bag_new(false))) return -1;
	if (!run_test(Bag_new(true))) return -1;

	return 0;
}
