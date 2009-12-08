#!/bin/bash

rm t*.sav.*
rm t*.error

# base case, load files (certs and roas only), run 5 different queries
# 1-1 all staleness filters yes
# 1-2 all staleness filters no
$RPKI_ROOT/testcases/runt.sh C.cer 1-1
$RPKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-2 1-2
$RPKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-3 1-3
$RPKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-4 1-4

