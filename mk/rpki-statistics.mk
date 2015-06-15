pkglibexec_SCRIPTS += bin/rpki-statistics/collect-statistics
MK_SUBST_FILES_EXEC += bin/rpki-statistics/collect-statistics
bin/rpki-statistics/collect-statistics: \
	$(srcdir)/bin/rpki-statistics/collect-statistics.in
PACKAGE_NAME_BINS += collect-statistics

pkglibexec_SCRIPTS += bin/rpki-statistics/plot-statistics
MK_SUBST_FILES_EXEC += bin/rpki-statistics/plot-statistics
bin/rpki-statistics/plot-statistics: \
	$(srcdir)/bin/rpki-statistics/plot-statistics.in
PACKAGE_NAME_BINS += plot-statistics


pkglibexec_SCRIPTS += bin/rpki-statistics/stats-for-each-run.sh
MK_SUBST_FILES_EXEC += bin/rpki-statistics/stats-for-each-run.sh
bin/rpki-statistics/stats-for-each-run.sh: \
	$(srcdir)/bin/rpki-statistics/stats-for-each-run.sh.in

pkglibexec_SCRIPTS += bin/rpki-statistics/stats-run-times.py
MK_SUBST_FILES_EXEC += bin/rpki-statistics/stats-run-times.py
bin/rpki-statistics/stats-run-times.py: \
	$(srcdir)/bin/rpki-statistics/stats-run-times.py.in


dist_plotexec_SCRIPTS +=  \
	bin/rpki-statistics/plots/run-times-over-time.R \
	bin/rpki-statistics/plots/run-times-over-time.sh \
	bin/rpki-statistics/plots/total-objects-over-time.R

plotexec_SCRIPTS += bin/rpki-statistics/plots/total-objects-over-time.sh
MK_SUBST_FILES_EXEC += bin/rpki-statistics/plots/total-objects-over-time.sh
bin/rpki-statistics/plots/total-objects-over-time.sh: \
	$(srcdir)/bin/rpki-statistics/plots/total-objects-over-time.sh.in


dist_statshelper_SCRIPTS += \
	bin/rpki-statistics/for-each-run-helpers/parse-results.sh \
	bin/rpki-statistics/for-each-run-helpers/rcli-important-messages.sh \
	bin/rpki-statistics/for-each-run-helpers/rcli-specific-messages-counts.sh

statshelper_SCRIPTS += \
	bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py
MK_SUBST_FILES_EXEC += \
	bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py
bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py: \
	$(srcdir)/bin/rpki-statistics/for-each-run-helpers/download-time-per-domain.py.in

statshelper_SCRIPTS += bin/rpki-statistics/for-each-run-helpers/validation-time.py
MK_SUBST_FILES_EXEC += \
	bin/rpki-statistics/for-each-run-helpers/validation-time.py
bin/rpki-statistics/for-each-run-helpers/validation-time.py: \
	$(srcdir)/bin/rpki-statistics/for-each-run-helpers/validation-time.py.in


examples_DATA += etc/statistics.conf
MK_SUBST_FILES += etc/statistics.conf
etc/statistics.conf: \
	$(srcdir)/etc/statistics.conf.in

pkgdata_DATA += var/statistics-internal.conf
MK_SUBST_FILES += var/statistics-internal.conf
var/statistics-internal.conf: \
	$(srcdir)/var/statistics-internal.conf.in
