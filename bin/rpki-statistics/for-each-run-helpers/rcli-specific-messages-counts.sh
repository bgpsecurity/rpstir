#!/bin/sh

# NOTE: this is untested

# Each argument is an egrep-style regular expression. For each regex, print
# the count of matching lines in rcli.log. Output is one line with
# tab-separated values.

get_count () {
    local regex

    regex="$1"
    shift

    egrep -- "$regex" rcli.log | wc -l
}

char_before_datum=""
for regex in "$@"; do
    printf "${char_before_datum}%s" `get_count "$regex"`
    char_before_datum="\t"
done
printf "\n"
