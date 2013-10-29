#!/bin/sh

awk '$7 == "Error" || $7 == "Warning"' < rcli.log | cut -d '|' -f 4-
