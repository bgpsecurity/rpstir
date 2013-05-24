## Handle $(ASN_BUILT_FILES) and $(ASN_SOURCE_FILES).


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
	$(ASN_BUILT_FILES) \
	$(ASN_SOURCE_FILES)

# This rule does all the generation work in a temporary directory and only
# generates one file (.c or .h) at a time. This is a bit wasteful in terms of
# number of copies and running asn_gen twice for each .asn file. However,
# make is not very good at handling the dependencies of recipes that generate
# multiple files and there are many pitfalls there. See
# http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
# for an overview.
$(ASN_C_FILES) $(ASN_H_FILES): $(ASN_GENERATION_DEPS)
	$(AM_V_GEN)tmpdir=`$(MKTEMP_DIR)` && \
	base=`echo "$(@F)" | $(SED) "s/\\.[ch]\$$//"` && \
	for f in $(ASN_BUILT_FILES); do \
		dir=`dirname "$$f"` && \
		mkdir -p "$$tmpdir/$$dir" && \
		cp "$$f" "$$tmpdir/$$dir"; \
	done && \
	for f in $(ASN_SOURCE_FILES); do \
		dir=`dirname "$$f"` && \
		mkdir -p "$$tmpdir/$$dir" && \
		cp "$(srcdir)/$$f" "$$tmpdir/$$dir"; \
	done && \
	cd "$$tmpdir/$(@D)" && \
	TEST_LOG_NAME="$(@F)" \
		TEST_LOG_DIR="$(abs_builddir)/$(@D)" \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) \
		$(abs_top_builddir)/lib/casn/asn_gen/asn_gen "$${base}.asn" && \
	cd "$(abs_builddir)" && \
	mkdir -p "$(@D)" && \
	cp "$$tmpdir/$@" "$(@D)" && \
	rm -rf "$$tmpdir"
