#
# Top level makefile
#
# $Id$
#

all:	cg.dir rsync_aur.dir roa-utils1.dir proto.dir roa-utils2.dir

cg.dir:
	cd cg && make

rsync_aur.dir:
	cd rsync_aur && make

roa-utils1.dir:
	cd roa-utils && make libroa.a

proto.dir:
	cd proto && make

roa-utils2.dir:
	cd roa-utils && make

clean:
	cd cg && make clean
	cd rsync_aur && make clean
	cd roa-utils && make clean
	cd proto && make clean
