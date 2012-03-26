#!/bin/bash

# This is only intended for the git branch demo.

for PID in `pgrep -u $USER -f rsync`
do
    kill $PID 2>/dev/null
done

if [ -n "$(pgrep -u $USER chaser)" ]; then
    kill "$(pgrep -u $USER chaser)"
fi

if [ -n "$(pgrep -u $USER chaser.sh)" ]; then
    kill "$(pgrep -u $USER chaser.sh)"
fi

for PID in `pgrep -u $USER -f demo_loop.sh`
do
    kill $PID 2>/dev/null
done

if [ -n "$(pgrep -u $USER garbage.sh)" ]; then
    kill "$(pgrep -u $USER garbage.sh)"
fi

if [ -n "$(pgrep -u $USER rsync_listener)" ]; then
    kill "$(pgrep -u $USER rsync_listener)"
fi

if [ -n "$(pgrep -u $USER rcli)" ]; then
    kill "$(pgrep -u $USER rcli)"
fi

if [ -n "$(pgrep -u $USER loader.sh)" ]; then
    kill "$(pgrep -u $USER loader.sh)"
fi

if [ -n "$(pgrep -u $USER rpstir-rtr-update)" ]; then
    kill "$(pgrep -u $USER rpstir-rtr-update)"
fi

if [ -n "$(pgrep -u $USER rpstir-rtrd)" ]; then
    kill "$(pgrep -u $USER rpstir-rtrd)"
fi

