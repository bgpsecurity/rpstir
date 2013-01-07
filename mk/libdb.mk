noinst_LIBRARIES += lib/db/libdb.a

LDADD_LIBDB = \
	lib/db/libdb.a

lib_db_libdb_a_SOURCES = \
	lib/db/clients/chaser.c \
	lib/db/clients/chaser.h \
	lib/db/clients/rtr.c \
	lib/db/clients/rtr.h \
	lib/db/connect.c \
	lib/db/connect.h \
	lib/db/db-internal.h \
	lib/db/prep-stmt.c \
	lib/db/prep-stmt.h \
	lib/db/util.c \
	lib/db/util.h
