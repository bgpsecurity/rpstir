#! /bin/sh

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $(which $0))
. $THIS_SCRIPT_DIR/../../../envir.setup

RCLI="${RPKI_ROOT}/proto/rcli"
REPOSITORY="${RPKI_ROOT}/testing/REPOSITORY"
ROOT_CERT="`/bin/pwd`/C.cer"
asID=8
tcType="roa"

while [ "x$1" != "x" ]; do
  if [ "x$1" = "x`echo $1 | sed -e \"s/^\-//\"`" ]; then
    tc=$1
    shift; continue
  fi

  case "$1" in
    "-roa" )
      tcType="roa"
      shift;;
    "-man" )
      tcType="man"
      shift;;
    * )
      echo "Unknown argument \"$1\""
      exit 1;;
  esac
done

if [ "x${tc}" = "x" ]; then
  echo -n "Test case: "
  read ans
  [ "x${ans}" = "x" ] && exit 0
fi

rawFile="`ls TC_${tc}.*.raw 2> /dev/null`"

if [ ! -f ${rawFile} ]; then
  if [ ${tcType} = "roa" -a -f ${certTemplate} ]; then
    gen_test_key C12.p15 && \
     make_test_cert C12 0D 1Y < ${certTemplate} && \
      gen_test_key C12R1.p15 && \
       make_test_cert C12R1 0D 1Y && \
        make_test_roa -c C12R1.cer -k C12R1.p15 -r ${targetFile} -R ${rawFile} -a ${asID}
    [ -f ${rawFile} ] || \
      (echo "Cannot generate \"${rawFile}\" from input certificate template \"${certTemplate}\""; exit 1) || \
	exit 1
  else
    [ -f ${rawTemplateFile} ] || \
      (echo "Cannot find \"${rawTemplateFile}\""; exit 1) || exit 1
    [ -f ${rawPatchFile} ] || \
      (echo "Cannot find \"${rawPatchFile}\""; exit 1) || exit 1

    echo "Making ${tcType} ${tc}..."
    cp ${rawTemplateFile} ${rawFile}
    patch -p0 < ${rawPatchFile} > /dev/null 2>&1 || \
      (echo "Cannot create patched ${tcType} \"${rawTemplateFile}\""; exit 1) || exit 1
  fi
fi

[ -f ${rawFile} ] || exit 1

[ "x${tcType}" = "x" ] && \
  tcType="`echo ${rawFile} | sed -e \"s/.*${tc}.\(.*\).raw/\1/\"`"

targetFile="TC_${tc}.${tcType}"
rawFile="${targetFile}.raw"
rawPatchFile="${rawFile}.patch"
rawTemplateFile="${tcType}.raw.orig"
certTemplate="makeCert_${tc}"

rr < ${rawFile} > ${targetFile} 2> /dev/null || \
  (echo "Error creating ${tcType} \"${targetFile}\""; exit 1) || exit 1

[ -f ${targetFile} ] || (echo "${tcType} \"${targetFile}\""; exit 1) || exit 1

(${RCLI} -x -y ; ${RCLI} -t ${REPOSITORY} -y ) > /dev/null 2>&1 || \
  (echo "Cannot initialize the database"; exit 1) || exit 1

echo "Adding certificates..."
${RCLI} -y -F ${ROOT_CERT} > /dev/null 2>&1 || \
    (echo "Cannot add ROOT certificate \"${ROOT_CERT}\""; exit 1) || exit 1

#certs="C1 C11 C11R1"
for cert in ${certs}; do
  ${RCLI} -y -f ${cert}.cer > /dev/null 2>&1 || \
    (echo "Cannot add certificate ${cert}"; exit 1) || exit 1
done

echo "Adding ${tcType} file ${targetFile}"
${RCLI} -y -f ${targetFile} || \
  (echo "Test ${tc} \"${targetFile}\" FAILED."; exit 1) && \
  echo "Test ${tc} \"${targetFile}\" PASSED."
