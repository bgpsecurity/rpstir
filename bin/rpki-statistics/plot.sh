#!/bin/sh

if test $# -eq 0; then
    echo >&2 "Usage: $0 <plot-name> [<plot-args> ...]"
    exit 1
fi

PLOT="$1"
shift

cd "$(dirname "$0")/plots"

# generate times.dat which can be used by all plots
{
    printf "Start\tEnd\n"
    for file in ../../../statistics/*.tgz; do
        basename "$file" .tgz
    done | sed -e 's/T/ /g' -e 's/~/\t/' | sort
} > times.dat

"./$PLOT.sh" "$@" > "./$PLOT.dat"
R -f "$PLOT.R"
