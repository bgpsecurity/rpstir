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
	$(LOG_COMPILER_DEPS) \
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
	$(AM_V_GEN)pecho() { printf %s\\n "$$*"; } ; \
	log() { pecho "$$@"; } ; \
	error() { log "ERROR: $$@" >&2; } ; \
	fatal() { error "$$@"; exit 1; } ; \
	try() { "$$@" || fatal "'$$@' failed"; } ; \
	tmpdir=$$(try $(MKTEMP_DIR)) || exit 1; \
	base=$$(echo "$(@F)" | try $(SED) "s/\\.[ch]\$$//") || exit 1; \
	for f in $(ASN_BUILT_FILES); do \
		dir=$$(try dirname "$$f") || exit 1; \
		try mkdir -p "$$tmpdir/$$dir"; \
		try cp "$$f" "$$tmpdir/$$dir"; \
	done; \
	for f in $(ASN_SOURCE_FILES); do \
		dir=$$(try dirname "$$f") || exit 1; \
		try mkdir -p "$$tmpdir/$$dir"; \
		try cp "$(srcdir)/$$f" "$$tmpdir/$$dir"; \
	done; \
	try cd "$$tmpdir/$(@D)"; \
	TEST_LOG_NAME="$(@F)" \
		TEST_LOG_DIR="$(abs_builddir)/$(@D)" \
		STRICT_CHECKS=0 \
		$(LOG_COMPILER) \
		$(abs_top_builddir)/lib/casn/asn_gen/asn_gen "$${base}.asn" \
		|| fatal "'$(LOG_COMPILER) asn_gen $${base}.asn' failed"; \
	try cd "$(abs_builddir)"; \
	try mkdir -p "$(@D)"; \
	try cp "$$tmpdir/$@" "$(@D)"; \
	try rm -rf "$$tmpdir"
