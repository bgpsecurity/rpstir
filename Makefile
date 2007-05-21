#
# Top level makefile
#
# $Id$
#

all:	cg.dir rsync_aur.dir roa-utils1.dir proto.dir roa-utils2.dir

cg.dir:
	cd cg && make all

rsync_aur.dir:
	cd rsync_aur && make all

roa-utils1.dir:
	cd roa-utils && make libroa.a

proto.dir:
	cd proto && make all

roa-utils2.dir:
	cd roa-utils && make all

clean:
	cd cg && make clean
	cd rsync_aur && make clean
	cd roa-utils && make clean
	cd proto && make clean
