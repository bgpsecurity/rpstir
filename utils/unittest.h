#ifndef _UTILS_UNITTEST_H
#define _UTILS_UNITTEST_H

#include <stdbool.h>
#include <stdio.h>

// Call like TEST(int, "%d", 1 + 1, ==, 2) to ensure that 1+1 == 2
#define TEST(type, fmt, value, condition, cmp_value) \
	do { \
		type _TEST_ ## __LINE__ ## _value = (value); \
		type _TEST_ ## __LINE__ ## _cmp_value = (cmp_value); \
		if (!(_TEST_ ## __LINE__ ## _value condition _TEST_ ## __LINE__ ## _cmp_value)) { \
			fprintf(stderr, "Failed test in " __FILE__ ":%d.\n", __LINE__); \
			fprintf(stderr, "    Expected: " #value " " #condition " " #cmp_value "\n"); \
			fprintf(stderr, "    Got LHS: " #value " = " fmt "\n", \
				_TEST_ ## __LINE__ ## _value); \
			fprintf(stderr, "    Got RHS: " #cmp_value " = " fmt "\n", \
				_TEST_ ## __LINE__ ## _cmp_value); \
			return false; \
		} \
	} while (false)

// Call like TEST_BOOL(true && true, true) to ensure that true && true is true
#define TEST_BOOL(value, cmp_value) \
	do { \
		bool _TEST_ ## __LINE__ ## _value = (value); \
		bool _TEST_ ## __LINE__ ## _cmp_value = (cmp_value); \
		if ((_TEST_ ## __LINE__ ## _value || _TEST_ ## __LINE__ ## _cmp_value) && \
			!(_TEST_ ## __LINE__ ## _value && _TEST_ ## __LINE__ ## _cmp_value)) \
		{ \
			fprintf(stderr, "Failed test in " __FILE__ ":%d.\n", __LINE__); \
			fprintf(stderr, "    Expected to be %s: " #value "\n", \
				(_TEST_ ## __LINE__ ## _cmp_value ? "true" : "false")); \
			return false; \
		} \
	} while (false)

#endif
