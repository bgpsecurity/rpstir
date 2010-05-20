#! /bin.sh

# ***** BEGIN LICENSE BLOCK *****
 #
 # BBN Address and AS Number PKI Database/repository software
 # Version 3.0-beta
 #
 # US government users are permitted unrestricted rights as
 # defined in the FAR.
 #
 # This software is distributed on an "AS IS" basis, WITHOUT
 # WARRANTY OF ANY KIND, either express or implied.
 #
 # Copyright (C) BBN Technologies 2010.  All Rights Reserved.
 #
 # Contributor(s): Mark Reynolds
 #
 # ***** END LICENSE BLOCK ***** */

l1Max=$1
l2Max=$2
l3Max=$3

[ "x${l1Max}" != "x" -a "x${l2Max}" != "x" -a "x${l3Max}" != "x" ] || exit 1
l1=1
while [ `expr ${l1} \<= ${l1Max}` = 1 ]; do
  l2=1
  while [ `expr ${l2} \<= ${l2Max}` = 1 ]; do
    l3=1
    while [ `expr ${l3} \<= ${l3Max}` = 1 ]; do
	dirName="`printf %d\/%05d\/%03d ${l1} ${l2} ${l3}`"
      mkdir -p ${dirName} > /dev/null 2>&1
#      echo -n "."

      l3=$(( $l3 + 1 ))
    done

#    echo
    l2=$(( $l2 + 1 ))
  done

  l1=$(( $l1 + 1 ))
done

