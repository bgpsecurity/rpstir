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
	DSN={MyODBC 3.51 Driver DSN};SERVER=localhost;DATABASE=test;USER=mysql
;

.end

#
# .tables section has the tables
#

.tables

apki_cert "CERTIFICATE" :
;

apki_crl "CRL" :
;

apki_roa "ROA" :
;

#
# The metadata table has information on when various operations
# have taken place, statistics, and other information that is not
# part of the PKI itself
#

apki_metadata "" :
;

.end
