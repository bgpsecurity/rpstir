pkglibexec_PROGRAMS += bin/rpki-rsync/rsync_aur

bin_rpki_rsync_rsync_aur_SOURCES = \
	bin/rpki-rsync/csapp.c \
	bin/rpki-rsync/csapp.h \
	bin/rpki-rsync/main.c \
	bin/rpki-rsync/main.h \
	bin/rpki-rsync/parse.c \
	bin/rpki-rsync/parse.h \
	bin/rpki-rsync/sig_handler.c \
	bin/rpki-rsync/sig_handler.h \
	bin/rpki-rsync/socket_stuff.c \
	bin/rpki-rsync/socket_stuff.h \
	bin/rpki-rsync/usage.c \
	bin/rpki-rsync/usage.h

bin_rpki_rsync_rsync_aur_LDADD = \
	$(LDADD_LIBUTIL) \
	$(LDADD_LIBCONFIG)

EXTRA_DIST += doc/rsync_aur.1


pkglibexec_SCRIPTS += bin/rpki-rsync/rsync_cord.py
MK_SUBST_FILES_EXEC += bin/rpki-rsync/rsync_cord.py
bin/rpki-rsync/rsync_cord.py: $(srcdir)/bin/rpki-rsync/rsync_cord.py.in


EXTRA_DIST += doc/AUR.readme
