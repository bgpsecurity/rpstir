#!/bin/bash

# This is only intended for the git branch demo.

if [ -n "$(pgrep -u $USER rpstir-rtrd)" ]; then
    kill "$(pgrep -u $USER rpstir-rtrd)"
fi

$RPKI_ROOT/rtr/rtrd &
