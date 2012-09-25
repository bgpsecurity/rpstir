#!/bin/sh

# Used to answer questions such as: "What % of certs/roas/etc... are invalid?"

# If one argument is specified, print that field.
# If two arguments are specified, compute the ratio of field $1 to field $2 in the results file.


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


if test $# -eq 1; then
    get_field_value "$1"
elif test $# -eq 2; then
    NUMERATOR=`get_field_value "$1"`
    DENOMINATOR=`get_field_value "$2"`

    awk "BEGIN {print $NUMERATOR * 1.0 / $DENOMINATOR}"
else
    echo >&2 "Usage:"
    echo >&2 "    $0 results-field"
    echo >&2 "    $0 results-field-for-numerator results-field-for-denominator"
    exit 1
fi
