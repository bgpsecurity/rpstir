#! /bin/sh
# makeit.sh -m1 3 -m2 1500 -m3 300
l1Start=1
l1Max=3

l2Start=1
l2Max=500

l3Start=1
l3Max=100

l1Prefixes="`pwd`/makeL1"
l2Prefixes="`pwd`/makeL2"
l3Prefixes="`pwd`/makeL3"

topcert="`pwd`/C.cer"
keyfile="`pwd`/C1.p15"

testdir="`pwd`/TEST"
unset fDebug fClean

LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}; export LD_LIBRARY_PATH
PATH=`pwd`:${RPKI_ROOT}/perftest:${RPKI_ROOT}/testcases:${PATH}; export PATH

help() {
echo "$0: [output dir] [-c] [-r] [-d] [-h]
          [-s1 <l1Start>] [-m1 <l1Max>] [-p1 <l1Prefixes>]
          [-s2 <l2Start>] [-m2 <l2Max>] [-p2 <l1Prefixes>]
          [-s3 <l3Start>] [-m3 <l3Max>] [-p3 <l1Prefixes>]"
}

usage() {
    help
echo "Where:
   -c      Remove the \"output dir\" before starting
   -d      Provide debug output
   -r      Create \"raw\" files
   -h      Help (this message)
   -s1     Starting items on level \"1\"
   -m1     Maximum items on level \"1\"
   -p1     Prefix assignments for level \"1\"
   -s2     Starting items on level \"2\"
   -m2     Maximum items on level \"2\"
   -p2     Prefix assignments for level \"2\"
   -s3     Starting items on level \"3\"
   -m3     Maximum items on level \"3\"
   -p3     Prefix assignments for level \"3\"
"
}

while [ "x$1" != "x" ]; do
  if [ "x`echo $1 | sed -e \"s/^\-//\"`" = "x$1" ]; then
    testdir=$1

    [ "x`echo ${testdir} | sed -e \"s/^\///\"`" = "x${testdir}" ] && \
	testdir="`pwd`/${testdir}"

    shift
    continue
  fi

  case "$1" in
    "-s1" )
      l1Start=$2; shift; shift;;

    "-s2" )
      l2Start=$2; shift; shift;;

    "-s3" )
      l3Start=$2; shift; shift;;

    "-m1" )
      l1Max=$2; shift; shift;;

    "-m2" )
      l2Max=$2; shift; shift;;

    "-m3" )
      l3Max=$2; shift; shift;;

    "-p1" )
      l1Prefixes=$2; shift; shift;;

    "-p2" )
      l2Prefixes=$2; shift; shift;;

    "-p3" )
      l3Prefixes=$2; shift; shift;;

    "-d" )
      fDebug="-d"; shift;;

    "-c" )
      fClean=yes; shift;;

    "-r" )
      fRaw="-r"; shift;;

    "-h" )
      usage
      shift
      exit 0
      ;;
    *)
      shift;;
  esac
done

[ "x${fClean}" != "x" ] && rm -rf ${testdir}

mkdir -p ${testdir} > /dev/null 2>&1 || exit 1

cd ${testdir}
cp ../C.cer ../C1.p15 .
#
# Make the top-level certs...
#
l1Entry=${l1Start}

make_perf_cert C1 ${l1Max} > /dev/null 2>&1 || exit 1
while [ `expr ${l1Entry} \<= ${l1Max}` = 1 ]; do
  l1Name=${l1Entry}
  l1Dir="${testdir}/${l1Name}"

  mkdir -p ${l1Dir} > /dev/null 2>&1 || exit 1

  (cd ${l1Dir}
   make_perf_cert C${l1Name}.00001 ${l2Max} > /dev/null 2>&1 || exit 1
  ) || exit 1

  l2Entry=${l2Start}
  while [ `expr ${l2Entry} \<= ${l2Max}` = 1 ]; do
    l2Name="`printf \"%05d\" ${l2Entry}`"
    l2Dir="${l1Dir}/${l2Name}"

    echo -n "${l1Name}:${l2Name}:"
    mkdir -p ${l2Dir} > /dev/null 2>&1 || exit

    (cd ${l2Dir}
     levelName="${l1Name}.${l2Name}"

     roaName="R${levelName}"

     make_perf_cert C${l1Name}.${l2Name}.001 ${l3Max} > /dev/null 2>&1 || exit 1
     make_perf_roa ${fDebug} -R R${l1Name}.${l2Name}.raw -r ${roaName} -k ${keyfile} || exit 1
    ) || exit 1


    l3Entry=${l3Start}
    while [ `expr ${l3Entry} \<= ${l3Max}` = 1 ]; do
      l3Name="`printf \"%03d\" ${l3Entry}`"
      l3Dir="${l2Dir}/${l3Name}"

      echo -n "."
      mkdir -p ${l3Dir} > /dev/null 2>&1 || exit

      (cd ${l3Dir}
       levelName="${l1Name}.${l2Name}.${l3Name}"

       roaName="R${levelName}"
       manName="M${levelName}"

       make_perf_roa ${fDebug} -R R${l1Name}.${l2Name}.${l3Name}.raw -r ${roaName} -k ${keyfile} || exit 1
       ls *.cer *.roa *.crl 2> /dev/null | grep -v [MR].cer > man.list && \
	 make_perf_manifest ${fDebug} -R ${manName}.raw -m ${manName} -k ${keyfile} < man.list || exit 1
       rm -f man.list C*[MR].cer > /dev/null 2>&1
       exit 0
      ) || exit 1

      l3Entry=$(( ${l3Entry} + 1 ))
    done

    (cd ${l2Dir}
     ls *.cer *.roa *.crl 2> /dev/null | grep -v [MR].cer > man.list && \
       make_perf_manifest ${fDebug} -R M${l1Name}.${l2Name}.raw -m M${l1Name}.${l2Name} -k ${keyfile} < man.list || exit 1
     rm -f man.list C*[MR].cer > /dev/null 2>&1
     exit 0
    ) || exit 1

    echo "(${l3Max})"
    l2Entry=$(( ${l2Entry} + 1 ))
  done
  
#  (cd ${l1Dir}
#   ls *.cer *.roa *.crl 2> /dev/null | grep -v [MR].cer > man.list && \
#     make_perf_manifest ${fDebug} -R M${l1Name}.raw -m M${l1Name} -k ${keyfile} < man.list || exit 1
#   rm -f man.list C*[MR].cer > /dev/null 2>&1
#   exit 0
#  ) || exit 1

   l1Entry=$(( ${l1Entry} + 1 ))
done

rm -f ${testdir}/C.cer ${teatdir}/C1.p15
#find ${testdir} -name "*.raw" -exec rm -f {} \;
