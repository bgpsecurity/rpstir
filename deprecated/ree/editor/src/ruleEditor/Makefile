
ifeq ($(shell uname -s),CYGWIN_NT-5.1)
        CP_DELIM = ;
else
	CP_DELIM = :
endif

JFLAGS = -g
.SUFFIXES: .java .class

CLASSPATH="../${CP_DELIM}../../lib"
OUTDIR="../../lib"


CLASSFILES = $(wildcard *.java)

default:	classes

classes: $(CLASSFILES:.java=.class)

.java.class:
	javac -cp ${CLASSPATH} -d ${OUTDIR} ${JFLAGS} $*.java
