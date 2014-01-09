#!/bin/sh

# Used to answer questions such as: "What % of certs/roas/etc... are invalid?"

# See usage() below for how to call this script.


get_field_value () {
    local field line

    if test $# -ne 1; then
        echo >&2 "get_field_value takes one argument"
        exit 1
    fi

    field=$1

    line=$(
        grep "^$field: [0-9]\\+$" results || {
            echo >&2 "can't find field \"$field\""
            exit 1
        }
    )

    echo "$line" | sed 's/^.*: \([0-9]\+\)$/\1/' || {
        echo >&2 "can't parse line: $line"
        exit 1
    }
}

usage () {
    echo >&2 "Usage:"
    echo >&2
    echo >&2 "    $0 all <results-field1> [<results-field2> ...]"
    echo >&2 "        print all the fields in order, separated by tabs"
    echo >&2
    echo >&2 "    $0 ratio <results-field-for-numerator> <results-field-for-denominator>"
    echo >&2 "        print the ratio of the two fields"
    exit 1
}

METHOD="$1"
shift || usage
case "$METHOD" in
    all)
        test $# -ge 1 || usage

        # Don't print anything before the first field,
        # but do print "\t" before each subsequent field.
        char_before_datum=""

        for field in "$@"; do
            printf "${char_before_datum}%s" "$(get_field_value "$field")"
            char_before_datum="\t"
        done
        printf "\n"
        ;;

    ratio)
        test $# -eq 2 || usage

        NUMERATOR=`get_field_value "$1"`
        DENOMINATOR=`get_field_value "$2"`

        awk "BEGIN {print $NUMERATOR * 1.0 / $DENOMINATOR}"
        ;;

    *)
        usage
        ;;
esac
