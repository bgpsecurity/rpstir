## Extra variables for use in flags.
PACKAGE_SYS_CONF_FILE = $(pkgsysconfdir)/$(PACKAGE_NAME).conf


AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g

AM_CPPFLAGS = \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/lib \
	-DABS_TOP_SRCDIR='"@abs_top_srcdir@"' \
	-DPACKAGE_SYS_CONF_FILE='"$(PACKAGE_SYS_CONF_FILE)"'

AM_ETAGSFLAGS = \
	--declarations
