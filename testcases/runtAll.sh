#!/bin/bash

rm t*.sav.*
rm t*.error

# base case, load files (certs and roas only), run 5 different queries
# 1-1 all staleness filters yes
# 1-2 all staleness filters no
$APKI_ROOT/testcases/runt.sh C.cer 1-1
$APKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-2 1-2
$APKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-3 1-3
$APKI_ROOT/testcases/runt.sh C.cer 1-1 1-1 1-4 1-4

