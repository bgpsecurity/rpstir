dist_bin_SCRIPTS += \
	bin/rpki-statistics/collect.sh


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
