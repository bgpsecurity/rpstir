#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#include "queue.h"
#include "unittest.h"

// TODO: Maybe add tests with 2 and 3 threads to truly exercise the mutexes.

static bool push_range(
    Queue * queue,
    ssize_t initial_size,
    uintptr_t start,
    uintptr_t stop)
{
    uintptr_t data;
    bool push_successful;

    for (data = start; data < stop; ++data)
    {
        push_successful = Queue_push(queue, (void *)data);
        TEST_BOOL(push_successful, true);
        TEST(ssize_t, "%zd", Queue_size(queue), ==,
             initial_size + (ssize_t) (data - start + 1));
    }

    return true;
}

static bool pop_range(
    Queue * queue,
    ssize_t initial_size,
    uintptr_t start,
    uintptr_t stop)
{
    uintptr_t data1;
    void *data2;
    bool pop_successful;

    for (data1 = start; data1 < stop; ++data1)
    {
        pop_successful = Queue_trypop(queue, &data2);
        TEST_BOOL(pop_successful, true);
        TEST(uintptr_t, "%" PRIuPTR, (uintptr_t) data2, ==, data1);
        TEST(ssize_t, "%zd", Queue_size(queue), ==,
             initial_size - (ssize_t) (data1 - start + 1));
    }

    return true;
}

static bool test_empty(
    Queue * queue)
{
    void *data;
    bool pop_successful;

    TEST(ssize_t, "%zd", Queue_size(queue), ==, 0);
    pop_successful = Queue_trypop(queue, &data);
    TEST_BOOL(pop_successful, false);
    TEST(ssize_t, "%zd", Queue_size(queue), ==, 0);

    return true;
}

static bool run_test(
    Queue * queue)
{
    TEST(void *,
         "%p",
             ((void *)queue),
         !=,
         NULL);

    if (!test_empty(queue))
        return false;

    if (!push_range(queue, 0, 0, 4000))
        return false;
    if (!pop_range(queue, 4000, 0, 1000))
        return false;
    if (!push_range(queue, 3000, 4000, 6000))
        return false;
    if (!pop_range(queue, 5000, 1000, 6000))
        return false;

    if (!test_empty(queue))
        return false;

    if (!push_range(queue, 0, 0, 1000))
        return false;
    if (!pop_range(queue, 1000, 0, 999))
        return false;
    if (!push_range(queue, 1, 1000, 6000))
        return false;
    if (!pop_range(queue, 5001, 999, 6000))
        return false;

    if (!test_empty(queue))
        return false;

    if (!push_range(queue, 0, 0, 2000))
        return false;
    if (!pop_range(queue, 2000, 0, 1998))
        return false;
    if (!push_range(queue, 2, 2000, 10000))
        return false;
    if (!pop_range(queue, 8002, 1998, 10000))
        return false;

    if (!test_empty(queue))
        return false;

    Queue_free(queue);

    return true;
}

int main(
    void)
{
    if (!run_test(Queue_new(true)))
        return -1;
    if (!run_test(Queue_new(false)))
        return -1;
    return 0;
}
