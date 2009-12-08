tar -cvf RPKI.tar cg/Makefile cg/asn/*.asn cg/asn/*.c cg/asn/Makefile cg/asn_gen/Makefile cg/asn_gen/*.[ch] cg/casn/Makefile cg/casn/*.[ch] cg/tools/Makefile cg/tools/*.[ch]
tar -rvf RPKI.tar doc license LOGS M* 
tar -rvf RPKI.tar proto/Makefile proto/*.[ch]  
tar -rvf RPKI.tar README REPOSITORY 
tar -rvf RPKI.tar roa-lib/Makefile roa-lib/*.[ch]  
tar -rvf RPKI.tar roa-utils/Makefile roa-utils/*.[ch]
tar -rvf RPKI.tar rsync_aur/Makefile rsync_aur/*.[ch] run_scripts 
tar -rvf RPKI.tar testcases/Makefile testcases/make* testcases/README testcases/*.[ch] testcases/C.cer testcases/C.raw testcases/*.p15
gzip RPKI.tar
