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

@sorted_parent_orgids =
    sort { $parent_orgid{ $a } <=> $parent_orgid{ $b } } keys %parent_orgid;

@sorted_parent_net_handles =
    reverse sort { $parent_net_handle{ $a } <=> $parent_net_handle{ $b } } keys %parent_net_handle;

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
#$level = 2;
#for $orgid (keys %orgid_parent) {
#    $orgid_level{$orgid} = $orgid_level{$orgid_parent{$orgid}} if exists $orgid_level{$orgid_parent{$orgid}};
#}

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
#for $orgid ( @sorted_parent_orgids ) {
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

for $orgid ( keys %parent_orgid ) {
    next if ( $parent_orgid{ $orgid } == 0 );
#    print "$orgid: $parent_orgid{ $orgid }\n" if ( $parent_orgid{ $orgid } >= 20000 );
    for $bin (@bins) {
	next if ( ($bin / $parent_orgid{ $orgid }) < 1 );
	$parent_bin{ $bin }++;
	last;
    }
}

for $bin_key ( sort {$a <=> $b} keys %parent_bin ) {
    print "$bin_key:\t\t$parent_bin{ $bin_key }\n";
}

##
## Now make a new hash, that is indexed by net handle and
## contains the AS
##
#foreach $handle (keys (%handle_to_net) ) {
#    $net_to_as{ $handle_to_net{ $handle } } =
#	$handle_to_as{ $handle };
#}

#for $net_handle (keys (%net_to_as) ) {
#    $as = $net_to_as{ $net_handle };
#
# Enable this to see the network prefixes
#
#    print "Prefix $net_handle: [$as] $parent_net_handle{ $net_handle }\n";
#}

#+++++
#for $net_handle ( @sorted_parent_net_handles ) {
#    $delegated_nets = $parent_net_handle{ $net_handle };
#    $total_parent_net_handles += $delegated_nets;
##
## Enable this to see the parented prefixes
##
#    print "Parent $net_handle: [$as]\t\t$delegated_netst\n";
##
##   The list is sorted by ascending value - the first fit is the best
##   fit...
##
#    for $bin (@bins) {
#	next if ( ($bin / $delegated_nets) < 1 );
#	$parent_bin{ $bin }++;
#	last;
#    }
##
## This one keeps track of every number
##
##    $parent_bin{ $parent_net{ $net_handle } }++;
#}
#
#for $bin_key ( sort {$a <=> $b} keys %parent_bin ) {
#    print "$bin_key:\t\t$parent_bin{ $bin_key }\n";
#}
#
#print "Total Prefixes:\t$total_parent_net_handles\n";
#-----
