bin_PROGRAMS += bin/rpki-rsync/rsync_aur

bin_rpki_rsync_rsync_aur_SOURCES =
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

dist_man_MANS += doc/rsync_aur.1


bin_PROGRAMS += bin/rpki-rsync/rsync_listener

bin_rpki_rsync_rsync_listener_SOURCES =
	bin/rpki-rsync/csapp.c \
	bin/rpki-rsync/csapp.h \
	bin/rpki-rsync/rsync_listener.c \
	bin/rpki-rsync/rsync_listener.h \


dist_doc_DATA += doc/AUR.readme
