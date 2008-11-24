#! /bin/sh

roaRawTemplateFile="roaTC.roa.raw.orig"

tc=$1
if [ "x${tc}" = "x" ]; then
  echo -n "Test case: "
  read ans
  [ "x${ans}" = "x" ] && exit 0
fi

roaFile="roaTC_${tc}.roa"
roaRawFile="${roaFile}.raw"
roaRawOrigFile="${roaFile}.raw.orig"
roaRawPatchFile="${roaFile}.raw.patch"

[ -f ${roaRawFile} ] || exit 1

cp -f ${roaRawTemplateFile} ${roaRawOrigFile}
diff -c ${roaRawOrigFile} ${roaRawFile} > ${roaRawPatchFile}

rm -f ${roaRawOrigFile}
