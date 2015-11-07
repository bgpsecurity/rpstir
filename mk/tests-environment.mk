## Anything that uses $(LOG_COMPILER) before "make all" finishes should
## depend on this.
LOG_COMPILER_DEPS = \
	etc/envir.setup \
	lib/util/shell_utils \
	tests/setup_test_environment.sh \
	tests/test.include
LOG_COMPILER = $(abs_top_builddir)/tests/setup_test_environment.sh
TEST_EXTENSIONS =

## TAP (test anything protocol) tests
TEST_EXTENSIONS += .tap
TAP_LOG_COMPILER = $(LOG_COMPILER)
# *_LOG_DRIVER variables are only supported with automake 1.12+, but
# the TAP test scripts still work with automake 1.11 (it just doesn't
# show the individual TAP test cases; the return value of the TAP test
# scripts determine pass or fail as usual)
TAP_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/build-aux/tap-driver.sh --ignore-exit
EXTRA_DIST += tests/tap4sh.sh

EXTRA_DIST += etc/test.conf

check_SCRIPTS += tests/setup_test_environment.sh
MK_SUBST_FILES_EXEC += tests/setup_test_environment.sh
tests/setup_test_environment.sh: $(srcdir)/tests/setup_test_environment.sh.in

check_DATA += tests/test.conf
MK_SUBST_FILES += tests/test.conf
tests/test.conf: $(srcdir)/tests/test.conf.in

noinst_DATA += tests/test.include
MK_SUBST_FILES += tests/test.include
tests/test.include: $(srcdir)/tests/test.include.in


# When $CHECKTOOL is set, extra log files can be generated. This rule cleans up
# those log files.
clean-local: clean-local-checktool-logs
.PHONY: clean-local-checktool-logs
clean-local-checktool-logs:
	find . -type f -name 'valgrind.*.log' -exec rm -f '{}' +


# Cat all the log files produced by self-tests.
# This is probably only useful to capture the log files in an automated build
# and test environment.
.PHONY: cat-logs
cat-logs:
	{ \
		for f in $(TEST_LOGS); do \
			echo "$$f"; \
			echo "$(distdir)/_build/$$f"; \
		done; \
		find . -type f -name 'valgrind.*.log' -print; \
	} | sort | uniq | while read log_file; do \
		if test -f "$$log_file"; then \
			echo "++++++ $$log_file ++++++"; \
			echo; \
			cat "$$log_file"; \
			echo; \
			echo; \
		fi; \
	done

EXTRA_DIST += tests/util.sh
