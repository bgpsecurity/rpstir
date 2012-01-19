#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "stringutils.h"
#include "unittest.h"


static bool test_scrub_for_print__length_if_truncated(void) {
    size_t const DST_LEN = 5;
    char src[] = "0123456789";
    char dst[DST_LEN];

    scrub_for_print(dst, src, DST_LEN);
    TEST(size_t, "%zu", strlen(dst), ==, DST_LEN - 1);

    return true;
}

static bool test_scrub_for_print__length_if_expansion_truncated(size_t const dst_len) {
    char src[50];
    char dst[dst_len];

    sprintf(src, "%c%c%s", 'a', '\n', "12345");

    scrub_for_print(dst, src, dst_len);

    TEST(size_t, "%zu", strlen(dst), ==, dst_len - 1);

    return true;
}

static bool test_scrub_for_print__null_input(void) {
    size_t const DST_LEN = 5;
    char src[] = "";
    char dst[DST_LEN];

    scrub_for_print(dst, src, DST_LEN);
    TEST(size_t, "%zu", strlen(dst), ==, 0);

    return true;
}

int main(void) {
	if (!test_scrub_for_print__length_if_truncated()) return EXIT_FAILURE;

	if (!test_scrub_for_print__length_if_expansion_truncated(1)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(2)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(3)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(4)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(5)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(6)) return EXIT_FAILURE;
	if (!test_scrub_for_print__length_if_expansion_truncated(7)) return EXIT_FAILURE;

    if (!test_scrub_for_print__null_input()) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
