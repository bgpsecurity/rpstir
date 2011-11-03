#include <stdbool.h>
#include <stdlib.h>

#include "queue.h"
#include "unittest.h"


static bool push_range(Queue * queue, ssize_t initial_size, void * start, void * stop)
{
	void * data;
	bool push_successful;

	for (data = start; data < stop; ++data)
	{
		push_successful = Queue_push(queue, data);
		TEST_BOOL(push_successful, true);
		TEST(ssize_t, "%zd", Queue_size(queue), ==, initial_size + (ssize_t)(data - start + 1));
	}

	return true;
}

static bool pop_range(Queue * queue, ssize_t initial_size, void * start, void * stop)
{
	void * data1;
	void * data2;
	bool pop_successful;

	for (data1 = start; data1 < (void*) stop; ++data1)
	{
		pop_successful = Queue_trypop(queue, &data2);
		TEST_BOOL(pop_successful, true);
		TEST(void*, "%p", data2, ==, data1);
		TEST(ssize_t, "%zd", Queue_size(queue), ==, initial_size - (ssize_t)(data1 - start + 1));
	}

	return true;
}

static bool test_empty(Queue * queue)
{
	void * data;
	bool pop_successful;

	TEST(ssize_t, "%zd", Queue_size(queue), ==, 0);
	pop_successful = Queue_trypop(queue, &data);
	TEST_BOOL(pop_successful, false);
	TEST(ssize_t, "%zd", Queue_size(queue), ==, 0);

	return true;
}

static bool run_test(Queue * queue)
{
	TEST(void *, "%p", ((void *)queue), !=, NULL);

	if (!test_empty(queue)) return false;

	if (!push_range(queue, 0, (void*)0, (void*)4000)) return false;
	if (!pop_range(queue, 4000, (void*)0, (void*)1000)) return false;
	if (!push_range(queue, 3000, (void*)4000, (void*)6000)) return false;
	if (!pop_range(queue, 5000, (void*)1000, (void*)6000)) return false;

	if (!test_empty(queue)) return false;

	if (!push_range(queue, 0, (void*)0, (void*)1000)) return false;
	if (!pop_range(queue, 1000, (void*)0, (void*)999)) return false;
	if (!push_range(queue, 1, (void*)1000, (void*)6000)) return false;
	if (!pop_range(queue, 5001, (void*)999, (void*)6000)) return false;

	if (!test_empty(queue)) return false;

	if (!push_range(queue, 0, (void*)0, (void*)2000)) return false;
	if (!pop_range(queue, 2000, (void*)0, (void*)1998)) return false;
	if (!push_range(queue, 2, (void*)2000, (void*)10000)) return false;
	if (!pop_range(queue, 8002, (void*)1998, (void*)10000)) return false;

	if (!test_empty(queue)) return false;

	Queue_free(queue);

	return true;
}

int main(void)
{
	if (!run_test(Queue_new(true))) return -1;
	if (!run_test(Queue_new(false))) return -1;
	return 0;
}
