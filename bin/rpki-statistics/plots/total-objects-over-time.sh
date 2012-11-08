#!/bin/sh

cd "$(dirname "$0")/../../.."

printf "%s\t%s\t%s\t%s\n" \
    "CACerts" \
    "CRLs" \
    "ROAs" \
    "MFTs"

./bin/rpki-statistics/for-each-run.sh \
    ./bin/rpki-statistics/for-each-run-helpers/parse-results.sh \
    all \
    "CA cert files" \
    "Total crl files" \
    "Total roa files" \
    "Total manifest files"
