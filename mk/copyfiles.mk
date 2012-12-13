## Handle $(COPYFILES).


BUILT_SOURCES += $(COPYFILES)

EXTRA_DIST += $(COPYFILES)

.PHONY: $(COPYFILES)
$(COPYFILES):
	if test '(' ! -e "$@" ')' -o "$(srcdir)/$@" -nt "$@"; then \
		mkdir -p "$(@D)"; \
		cp -a "$(srcdir)/$@" "$@"; \
		chmod +w "$@"; \
	fi

clean-local: clean-local-copyfiles
.PHONY: clean-local-copyfiles
clean-local-copyfiles:
	if test "$(srcdir)" != "$(builddir)"; then \
		rm -f $(COPYFILES); \
	fi
