tar -cvf APKI.tar cg/Makefile cg/asn/*.asn cg/asn/*.c cg/asn/Makefile cg/asn_gen/Makefile cg/asn_gen/*.[ch] cg/casn/Makefile cg/casn/*.[ch] cg/tools/Makefile cg/tools/*.[ch]
tar -rvf APKI.tar doc license LOGS M* 
tar -rvf APKI.tar proto/Makefile proto/*.[ch]  
tar -rvf APKI.tar README REPOSITORY 
tar -rvf APKI.tar roa-lib/Makefile roa-lib/*.[ch]  
tar -rvf APKI.tar roa-utils/Makefile roa-utils/*.[ch]
tar -rvf APKI.tar rsync_aur/Makefile rsync_aur/*.[ch] run_scripts 
tar -rvf APKI.tar testcases/Makefile testcases/make* testcases/README testcases/*.[ch] testcases/C.cer testcases/C.raw testcases/*.p15
gzip APKI.tar
