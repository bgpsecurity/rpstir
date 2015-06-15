## Handle $(PACKAGE_NAME_BINS)

install-exec-hook: install-exec-hook-package-name-bins
.PHONY: install-exec-hook-package-name-bins
install-exec-hook-package-name-bins:
	mkdir -p $(DESTDIR)$(bindir)
	. $(srcdir)/lib/util/shell_utils; \
	cd $(DESTDIR)$(bindir); \
	pkglibexecdir_rel="$$(relpath "$(DESTDIR)$(pkglibexecdir)")"; \
	for file in $(PACKAGE_NAME_BINS); do \
		rm -f "$(PACKAGE_NAME)-$$file"; \
		$(LN_S) "$$pkglibexecdir_rel/$$file" \
			"$(PACKAGE_NAME)-$$file"; \
	done

uninstall-local: uninstall-local-package-name-bins
.PHONY: uninstall-local-package-name-bins
uninstall-local-package-name-bins:
	for file in $(PACKAGE_NAME_BINS); do \
		rm -f "$(DESTDIR)$(bindir)/$(PACKAGE_NAME)-$$file"; \
	done
