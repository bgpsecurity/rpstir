#! /bin/sh

for inFile in $*; do
  outFile=`echo ${inFile} | sed -e "s/.pem//"`
  [ "x${outFile}" = "x${inFile}" ] && \
    continue
   echo "${inFile} ==> ${outFile}"
  (./un64 ${inFile} && mv out.bin ${outFile}) > /dev/null 2>&1
done
