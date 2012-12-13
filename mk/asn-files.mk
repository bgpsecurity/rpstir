## Handle $(ASN_BUILT_FILES) and $(ASN_SOURCE_FILES).


CLEANFILES += copy-asn-sources-stamp

copy-asn-sources-stamp: $(ASN_SOURCE_FILES)
	if test "$(builddir)" != "$(srcdir)"; then \
		for file in $(ASN_SOURCE_FILES); do \
			mkdir -p "$(builddir)"/`dirname "$$file"`; \
			cp -f "$(srcdir)/$$file" "$(builddir)/$$file"; \
		done; \
	fi
	touch "$@"

clean-local: clean-local-asn-copies
.PHONY: clean-local-asn-copies
clean-local-asn-copies:
	if test "$(builddir)" != "$(srcdir)"; then \
		for file in $(ASN_SOURCE_FILES); do \
			rm -f "$(builddir)/$$file"; \
		done; \
	fi


ASN_C_FILES = $(ASN_BUILT_FILES:.asn=.c) $(ASN_SOURCE_FILES:.asn=.c)
ASN_H_FILES = $(ASN_BUILT_FILES:.asn=.h) $(ASN_SOURCE_FILES:.asn=.h)

EXTRA_DIST += $(ASN_SOURCE_FILES)

CLEANFILES += \
	$(ASN_BUILT_FILES) \
	$(ASN_C_FILES) \
	$(ASN_H_FILES)

BUILT_SOURCES += $(ASN_H_FILES)

# Depend on all .asn files because .asn files can include one another.
ASN_GENERATION_DEPS = \
	lib/casn/asn_gen/asn_gen \
	$(TESTS_ENVIRONTMENT_DEPS) \
	copy-asn-sources-stamp \
	$(ASN_BUILT_FILES)

$(ASN_C_FILES) $(ASN_H_FILES): $(ASN_GENERATION_DEPS)
	mkdir -p "$(@D)"
	base=`echo "$(@F)" | $(SED) "s/\\.[ch]\$$//"`; \
	cd "$(@D)" && \
		TEST_LOG_NAME="$$base" \
		TEST_LOG_DIR=. \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) \
		$(abs_top_builddir)/lib/casn/asn_gen/asn_gen "$${base}.asn"

# Prevent race condition in parallel make where foo.c and foo.h could both
# trigger the above rule at the same time.
$(ASN_C_FILES): $(ASN_H_FILES)
