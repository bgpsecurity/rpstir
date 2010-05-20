#! /usr/bin/perl
# ***** BEGIN LICENSE BLOCK *****
# 
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
# 
#  US government users are permitted unrestricted rights as
#  defined in the FAR.
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) BBN Technologies 2010.  All Rights Reserved.
# 
#  Contributor(s): Mark Reynolds
# 
#  ***** END LICENSE BLOCK ***** */

#gunzip -c arin_db.txt.gz | sed -e "1,65d" | ./arin_db.pl >arin_db.txt

$record = "";
while ( defined( $line = <STDIN> ) ) {
    chomp( $line);

    if ( length( $line) ) {
	($var, $val) = split(/:/, $line);
	next if ( $var =~ m/Comment/i ) ;

	$val =~ s/^\s+//;

	$record .= "$var=$val\:\:";
	next;
    }


    chop( $record);
    chop( $record);
    print "$record\n";
    $record = "";
}
