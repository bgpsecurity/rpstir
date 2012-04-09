#!/bin/sh -e
#This builds all necessary Makefile.in's and other necessary files and then generates
# the configure script.
autoreconf --force --install --verbose
