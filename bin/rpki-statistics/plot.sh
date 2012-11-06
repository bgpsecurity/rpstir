#!/bin/sh

if test $# -eq 0; then
    echo >&2 "Usage: $0 <plot-name> [<plot-args> ...]"
    exit 1
fi

PLOT="$1"
shift

cd "$(dirname "$0")/plots"

"./$PLOT.sh" > "./$PLOT.dat"
R -f "$PLOT.r"
