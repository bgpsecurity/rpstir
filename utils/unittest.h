#ifndef _UTILS_UNITTEST_H
#define _UTILS_UNITTEST_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// Call like TEST(int, "%d", 1 + 1, ==, 2) to ensure that 1+1 == 2
#define TEST(type, fmt, value, condition, cmp_value) \
	do { \
		type _TEST_ ## __LINE__ ## _value = (value); \
		type _TEST_ ## __LINE__ ## _cmp_value = (cmp_value); \
		if (!(_TEST_ ## __LINE__ ## _value condition _TEST_ ## __LINE__ ## _cmp_value)) { \
			fprintf(stderr, "Failed test in %s:%d.\n", __FILE__, __LINE__); \
			fprintf(stderr, "    Expected: %s %s %s\n", #value, #condition, #cmp_value); \
			fprintf(stderr, "    Got LHS: %s = " fmt "\n", \
				#value, \
				_TEST_ ## __LINE__ ## _value); \
			fprintf(stderr, "    Got RHS: %s = " fmt "\n", \
				#cmp_value, \
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
			fprintf(stderr, "Failed test in %s:%d.\n", __FILE__, __LINE__); \
			fprintf(stderr, "    Expected to be %s: %s\n", \
				(_TEST_ ## __LINE__ ## _cmp_value ? "true" : "false"), \
				#value); \
			return false; \
		} \
	} while (false)

// Call like TEST_STR("foo", !=, "bar")
#define TEST_STR(value, condition, cmp_value) \
	do { \
		const char * _TEST_ ## __LINE__ ## _value = (value); \
		const char *  _TEST_ ## __LINE__ ## _cmp_value = (cmp_value); \
		if (!(strcmp(_TEST_ ## __LINE__ ## _value, _TEST_ ## __LINE__ ## _cmp_value) \
			condition 0)) \
		{ \
			fprintf(stderr, "Failed test in %s:%d.\n", __FILE__, __LINE__); \
			fprintf(stderr, "    Expected: %s %s %s\n", #value, #condition, #cmp_value); \
			fprintf(stderr, "    Got LHS: %s = \"%s\"\n", \
				#value, \
				_TEST_ ## __LINE__ ## _value); \
			fprintf(stderr, "    Got RHS: %s = \"%s\"\n", \
				#cmp_value, \
				_TEST_ ## __LINE__ ## _cmp_value); \
			return false; \
		} \
	} while (false)

#endif
