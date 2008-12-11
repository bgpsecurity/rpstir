#!/usr/bin/perl

$APKI_ROOT = "/home/gardiner/apki/trunk";
# Check these before running!
$mcert = "$APKI_ROOT/perftest/make_perf_cert";
$logfile = "$APKI_ROOT/perftest/certlog.txt";
print "$APKI_ROOT/perftest/APKI\n";

# Start in dir APKI
chdir "$APKI_ROOT/perftest/APKI";

# Derrick's test values.  Ignore for real running
#$mcert = "/Users/starflt/Documents/SA/Newtest/perftest/make_perf_cert";
#$logfile = "/Users/starflt/Documents/SA/Newtest/perftest/logfile.txt";
#chdir "/Users/starflt/Documents/SA/Newtest/perftest/APKI";

system("/bin/rm -rf *");
system("echo \"cd+++++++ ./\" > $logfile");
system("/bin/cp ../C.cer ../C.p15 .");
system("$mcert C1 1 256 >> $logfile");
mkdir "1";
chdir "1";
system("$mcert C1.00001 2412 17 >> $logfile");
system("$mcert C1.03001 882 1 >> $logfile");

# Do dirs C1.00001 through C2.00003
for ($i=1;$i<=3;$i++) {
    $dir = "0000" . "$i";
    mkdir "$dir";
    chdir "$dir";
    system("$mcert C1.$dir.001 999 5 >> $logfile");
    for ($j=1;$j<=999;$j++) {
	$formatj = sprintf "%03d", $j;
	mkdir "$formatj";
	chdir "$formatj";
	system("$mcert C1.$dir.$formatj. 1 1 >> $logfile");
	chdir "..";
    }
    chdir "..";
}

# Do dir C1.00004
$dir = "00004";
mkdir "$dir";
chdir "$dir";
system("$mcert C1.$dir.001 113 5 >> $logfile");
for ($j=1;$j<=113;$j++) {
    $formatj = sprintf "%03d", $j;
    mkdir "$formatj";
    chdir "$formatj";
    system("$mcert C1.$dir.$formatj. 1 1 >> $logfile ");
    chdir "..";
}
chdir "..";

# Do dirs C1.00010 through C1.00012
for ($i=10;$i<=12;$i++) {
    $dir = "000" . "$i";
    mkdir "$dir";
    chdir "$dir";
    system("$mcert C1.$dir.001 999 1 >> $logfile");
    for ($j=1;$j<=999;$j++) {
	$formatj = sprintf "%03d", $j;
	mkdir "$formatj";
	chdir "$formatj";
	system("$mcert C1.$dir.$formatj. 1 1 >> $logfile");
	chdir "..";
    }
    chdir "..";
}

# Do dir C1.00013
$dir = "00013";
mkdir "$dir";
chdir "$dir";
system("$mcert C1.$dir.001 529 1 >> $logfile");
for ($j=1;$j<=529;$j++) {
    $formatj = sprintf "%03d", $j;
    mkdir "$formatj";
    chdir "$formatj";
    system("$mcert C1.$dir.$formatj. 1 1 >> $logfile");
    chdir "..";
}
chdir "..";
