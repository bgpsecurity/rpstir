noinst_LIBRARIES += lib/rpki-rtr/librpkirtr.a

lib_rpki_rtr_librpkirtr_a_SOURCES = \
	lib/rpki-rtr/pdu.c \
	lib/rpki-rtr/pdu.h

lib_rpki_rtr_librpkirtr_a_CFLAGS = \
	$(CFLAGS_STRICT)
