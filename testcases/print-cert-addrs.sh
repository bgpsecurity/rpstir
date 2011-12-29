#!/bin/sh


# print the ipv4 addresses in the makeC* files to check the hierarchy

for i in makeC*; do 
    printf "%-10s %s\n" $i: `head -1 $i`
done
