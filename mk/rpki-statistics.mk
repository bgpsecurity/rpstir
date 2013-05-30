pkglibexec_SCRIPTS += bin/rpki-statistics/collect-statistics
MK_SUBST_FILES_EXEC += bin/rpki-statistics/collect-statistics
bin/rpki-statistics/collect-statistics: \
	$(srcdir)/bin/rpki-statistics/collect-statistics.in
PACKAGE_NAME_BINS += collect-statistics


noinst_SCRIPTS += bin/rpki-statistics/for-each-run.sh
MK_SUBST_FILES_EXEC += bin/rpki-statistics/for-each-run.sh
bin/rpki-statistics/for-each-run.sh: \
	$(srcdir)/bin/rpki-statistics/for-each-run.sh.in


noinst_SCRIPTS += \
	bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py
MK_SUBST_FILES_EXEC += \
	bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py
bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py: \
	$(srcdir)/bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py.in


noinst_SCRIPTS += bin/rpki-statistics/for-each-run-helpers/validation-time.py
MK_SUBST_FILES_EXEC += \
	bin/rpki-statistics/for-each-run-helpers/validation-time.py
bin/rpki-statistics/for-each-run-helpers/validation-time.py: \
	$(srcdir)/bin/rpki-statistics/for-each-run-helpers/validation-time.py.in


noinst_SCRIPTS += bin/rpki-statistics/run-times.py
MK_SUBST_FILES_EXEC += bin/rpki-statistics/run-times.py
bin/rpki-statistics/run-times.py: $(srcdir)/bin/rpki-statistics/run-times.py.in


examples_DATA += etc/statistics.conf
MK_SUBST_FILES += etc/statistics.conf
etc/statistics.conf: \
	$(srcdir)/etc/statistics.conf.in

pkgdata_DATA += var/statistics-internal.conf
MK_SUBST_FILES += var/statistics-internal.conf
var/statistics-internal.conf: \
	$(srcdir)/var/statistics-internal.conf.in
