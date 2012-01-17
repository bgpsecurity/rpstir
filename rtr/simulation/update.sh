#!/bin/sh -e

. "`dirname "$0"`/../../envir.setup"

$RPKI_MYSQL_CMD < "`dirname "$0"`/update.sql"
