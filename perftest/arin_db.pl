#! /usr/bin/perl
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
