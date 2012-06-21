noinst_LIBRARIES += lib/rpki/librpki.a

lib_rpki_librpki_a_SOURCES = \
	lib/rpki/cms/roa_create.c \
	lib/rpki/cms/roa_general.c \
	lib/rpki/cms/roa_serialize.c \
	lib/rpki/cms/roa_utils.h \
	lib/rpki/cms/roa_validate.c \
	lib/rpki/cms/signCMS.c \
	lib/rpki/conversion.c \
	lib/rpki/conversion.h \
	lib/rpki/db_constants.h \
	lib/rpki/diru.c \
	lib/rpki/diru.h \
	lib/rpki/err.c \
	lib/rpki/err.h \
	lib/rpki/globals.h \
	lib/rpki/initscm.c \
	lib/rpki/myssl.c \
	lib/rpki/myssl.h \
	lib/rpki/querySupport.c \
	lib/rpki/querySupport.h \
	lib/rpki/rpcommon.c \
	lib/rpki/rpwork.c \
	lib/rpki/rpwork.h \
	lib/rpki/scmf.h \
	lib/rpki/scm.h \
	lib/rpki/scmmain.h \
	lib/rpki/sqcon.c \
	lib/rpki/sqhl.c \
	lib/rpki/sqhl.h
