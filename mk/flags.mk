AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-g

AM_CPPFLAGS = \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/lib \
	-DABS_TOP_SRCDIR='"@abs_top_srcdir@"' \
	-DSYSCONFDIR='"$(sysconfdir)"'

AM_ETAGSFLAGS = \
	--declarations
