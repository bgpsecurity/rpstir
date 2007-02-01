#
# $Id$
#
# Configuration file for the db schema
#

#
# .dsn section has the DSN name
#

.dsn

DSN :
	{MyODBC 3.51 Driver DSN};SERVER=localhost;DATABASE=test;USER=mysql
;

.end

#
# .tables section has the tables
#

.tables 5

TABLE apki_cert "CERTIFICATE" :
;

TABLE apki_crl "CRL" :
;

TABLE apki_roa "ROA" :
;

TABLE apki_dir "DIRECTORY" :
;

#
# The metadata table has information on when various operations
# have taken place, statistics, and other information that is not
# part of the PKI itself
#

TABLE apki_metadata "" :
;

.end
