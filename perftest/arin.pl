#! /usr/bin/perl
#cat arin.txt | parents.pl > parents.txt

my $parents = {};
my $handle_to_net = {};
my $handle_to_as = {};

@bins = (
	 "1",
	 "2",
         "5",
	 "10",
	 "20",
	 "50",
	 "100",
	 "200",
	 "500",
	 "1000",
	 "2000",
	 "5000",
	 "10000",
	 "20000",
	 "50000",
	 "100000",
	 "200000",
	 "500000",
	 "1000000",
	 "2000000",
	 "5000000",
	 );

while ( defined( $line = <STDIN>) ) {
    chomp( $line);

    my $tech_handle="";
    my $as="";
    my $net_handle="";
    my $orgid="";
    my $parent="";

    my @fields = split(/::/,$line);

    #
    # Read each line and populate some variables of interest...
    #    techhandle, as, nethandle, orgid
    #
    for $field ( @fields ) {
	($var,$val) = split( /=/, $field);

	$tech_handle = $val if ( $var =~ m/techhandle/i );
	$as = $val if ( $var =~ m/asnumber/i );
	$net_handle = $val if ( $var =~ m/nethandle/i );
	$orgid = $val if ( $var =~ m/orgid/i );
	$parent = $val if ( $var =~ m/parent/i );
    }

# Record parent for each orgid
    $orgid_parent{$orgid} = $parent if length($parent);

    push( @direct_orgids,$orgid )
	if ( ((!length $parent) && (length $net_handle)) ||
	     ((length $parent) && ($parent eq $net_handlle)) );

    $parent_net_handle{ $parent }++
	if ( length $parent && ($parent ne $net_handle) );

    #
    # Pick up the mapping between Organization ID and "network handle"
    #
    if ( length $orgid ) {
        if ( length $net_handle ) {
	    $net_to_orgid{ $net_handle } = $orgid;

	    $orgid_to_net{ $orgid } = [] unless exists $orgid_to_net{ $orgid };
	    push @{ $orgid_to_net{ $orgid } },$net_handle;
	}
	if ( length $as ) {
	    $as_to_orgid{ $net_handle } = $orgid;

	    $orgid_to_as{ $orgid } = [] unless exists $orgid_to_as{ $orgid };
	    push @{ $orgid_to_as{ $orgid } },$as;
	}
    }

    #
    # Start the process of mapping "nework handle" to AS number
    # This currently requires 2 arrays, which are combined later...
    #
    if ( length $tech_handle ) {
	$handle_to_net{ $tech_handle } = $net_handle if ( length $net_handle );
	$handle_to_as{ $tech_handle } = $as if ( length $as );
    }
}

#++
#foreach $orgid (keys %orgid_to_net) {
#    print "$orgid: $orgid_to_net{ $orgid }\n";
#}
#--

foreach $handle (keys %parent_net_handle) {
    $parent_orgid{ $net_to_orgid{ $handle } } +=
	$parent_net_handle{ $handle };
}

my %direct_hash = map { $_, 1 } @direct_orgids;
@direct_orgids = keys %direct_hash;

# Generate level of each orgid.

# Level 1 = ARIN
# Level 2 = orgs that are directly allocated space by ARIN
# Level 3 = orgs allocated space by level 2 entities

# Level 1 (roots)
for $direct (@direct_orgids) {
    $orgid_level{$direct} = 1;
}

$found = 1;
while ($found == 1) {
    $found = 0;
    for $orgid (keys %orgid_parent) {
	next if (exists $orgid_level{$orgid});
	next if (! exists $orgid_level{$net_to_orgid{$orgid_parent{$orgid}}});
	$parent_level = $orgid_level{$net_to_orgid{$orgid_parent{$orgid}}};
	$orgid_level{$orgid} = $parent_level + 1;
	$found = 1;
    }
}

#
# This dumps the table of the number of delegates by origanization
#
#for $orgid ( sort {$a <=> $b} keys %parent_orgid ) {
for $orgid ( keys %parent_orgid ) {
    if (! exists $orgid_level{$orgid}) { 
	$thislevel = "<null>";
    }
    else {
	$thislevel = $orgid_level{$orgid};
    }
    if (! exists $net_to_orgid{$orgid_parent{$orgid}}) { 
	$thisparent = "<null>";
    }
    else {
	$thisparent = $net_to_orgid{$orgid_parent{$orgid}};
    }
    print "Delegating organization $orgid: [@{$orgid_to_as{ $orgid }}] Level = $thislevel, Parent = $thisparent, $parent_orgid{$orgid }\n";

    for $net_handle (@{ $orgid_to_net{ $orgid } }) {
	print "    $net_handle: $parent_net_handle{ $net_handle }\n";
#	    if ( exists $parent_net_handle{ $net_handle } )
    }
}

$direct_orgids = @direct_orgids;
print "Non-delegating organizations [$direct_orgids]: @direct_orgids\n";

#++
#for $orgid ( keys %parent_orgid ) {
#    next if ( $parent_orgid{ $orgid } == 0 );
##    print "$orgid: $parent_orgid{ $orgid }\n" if ( $parent_orgid{ $orgid } >= 20000 );
#    for $bin (@bins) {
#	next if ( ($bin / $parent_orgid{ $orgid }) < 1 );
#	$parent_bin{ $bin }++;
#	last;
#    }
#}
#
#for $bin_key ( sort {$a <=> $b} keys %parent_bin ) {
#    print "$bin_key:\t\t$parent_bin{ $bin_key }\n";
#}
#--

$level=1;
$found=1;
while ( $found == 1 ) {
    $found = 0;
    for $orgid ( keys %orgid_level ) {
	if ( $orgid_level{ $orgid } == $level ) {
	    $asses = $#{$orgid_to_as{ $orgid }} + 1;
	    $level_as{ $level } += $asses;
	    $found = 1;
	}
    }
    $level += 1;
}

for $level ( sort {$a <=> $b} keys %level_as ) {
    print "Level $level: $level_as{ $level }\n";
}
