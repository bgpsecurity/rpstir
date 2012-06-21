bin_PROGRAMS += bin/rpki/chaser

bin_rpki_chaser_LDADD = \
	lib/db/libdb.a


bin_PROGRAMS += bin/rpki/garbage

bin_rpki_garbage_LDADD = \
	lib/rpki/librpki.a


dist_bin_SCRIPTS += bin/rpki/garbage.sh


dist_bin_SCRIPTS += bin/rpki/initDB.sh


dist_bin_SCRIPTS += bin/rpki/loader.sh


bin_PROGRAMS += bin/rpki/query

bin_rpki_query_LDADD = \
	lib/rpki/librpki.a


dist_bin_SCRIPTS += bin/rpki/query.sh


bin_PROGRAMS += bin/rpki/rcli

bin_rpki_rcli_LDADD = \
	lib/rpki/librpki.a


dist_sysconf_DATA += etc/sampleQuerySpecs
