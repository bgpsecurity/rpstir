## Handle $(COPYFILES).


BUILT_SOURCES += $(COPYFILES)

EXTRA_DIST += $(COPYFILES)

.PHONY: $(COPYFILES)
$(COPYFILES):
	@fatal () { echo >&2 "*** $$*"; exit 1; }; \
	if test '(' ! -e "$@" ')' -o "$(srcdir)/$@" -nt "$@"; then \
		mkdir -p "$(@D)" || fatal "Can't create directory $(@D)"; \
		cp -a "$(srcdir)/$@" "$@" || fatal "Can't copy $(srcdir)/$@ to $@"; \
		chmod +w "$@" || fatal "Can't make $@ writeable"; \
	fi

clean-local: clean-local-copyfiles
.PHONY: clean-local-copyfiles
clean-local-copyfiles:
	if test "$(srcdir)" != "$(builddir)"; then \
		rm -f $(COPYFILES); \
	fi
