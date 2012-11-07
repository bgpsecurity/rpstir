#!/bin/sh

cd "$(dirname "$0")/../../.."

./bin/rpki-statistics/run-times.py
