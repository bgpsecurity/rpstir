$RPKI_ROOT/run_scripts/initDB.sh
rcli -y -F ../root.cer
# rcli -y -f badCert2AKI.cer                # Duplicate AKI (-59)
# rcli -y -f badCert2ASNum.cer              # Duplicate AS# resources (-80)
# rcli -y -f badCert2BasicConstr.cer            # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCert2Cpol.cer               # Duplicate policy ext (-75)
# rcli -y -f badCert2CRLDP.cer              # Duplicate CRLDP (-64)
# rcli -y -f badCert2IPAddr.cer             # Duplicate IP resources (-79)
# rcli -y -f badCert2KeyUsage.cer               # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCert2SKI.cer                # Duplicate SKI (-56)
# rcli -y -f badCertAIA2AccessDesc.cer      # Duplicate AIA (-69)
# rcli -y -f badCertAIA2x.cer               # Duplicate AIA (-69)
# rcli -y -f badCertAIAAccessLoc.cer        # AIA not a URI (-70)
# rcli -y -f badCertAIABadAccess.cer        # AIA not a URI (-70)
# rcli -y -f badCertAIACrit.cer                 # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertAKIHash.cer                 # I think a bad AKI hash should be added to the DB normally and garbage collected eventually. -- David Mandelberg
# rcli -y -f badCertAKILth.cer              # Invalid AKI (-115)
# rcli -y -f badCertBadExtension1.cer       # Unless the extension is critical, it's fine to ignore an unknown extension. (http://tools.ietf.org/html/draft-ietf-sidr-res-certs-22#section-4.8)
# rcli -y -f badCertBasicConstrNoCA.cer         # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertBasicConstrNoCrit.cer   # Extension must be critical (-48)
# rcli -y -f badCertBasicConstrPathLth.cer  # Pathlen invalid (-50)
# rcli -y -f badCertCpol2oid.cer            # Duplicate policy ext (-75)
# rcli -y -f badCertCpolNoCrit.cer          # Extension must be critical (-48)
# rcli -y -f badCertCRLDP2DistPt.cer            # It looks like a CRLDP with two URIs is allowed: http://tools.ietf.org/html/draft-ietf-sidr-res-certs-22#section-4.8.6
# rcli -y -f badCertCRLDPCrit.cer               # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertCRLDPCrlIssuer.cer      # CRLDP with subfields (-65)
# rcli -y -f badCertCRLDPNoDistPt.cer           # Cannot get CRLDP name field (-66) #cg-110927:  this looks odd
# rcli -y -f badCertCRLDPReasons.cer        # CRLDP with subfields (-65)
# rcli -y -f badCertEKU.cer                     # Invalid certificate flags (-46) # cg-110927:  this should have a stronger error message than bad flags
# rcli -y -f badCertInnerSigAlg.cer         # Differing algorithms in cert (-95)
# rcli -y -f badCertIssuer2ComName.cer      # Invalid issuer name (-114)
# rcli -y -f badCertIssuer2SerNums.cer      # Invalid issuer name (-114)
# rcli -y -f badCertIssuer2SetComName.cer       # Invalid subject name (-113)
# rcli -y -f badCertIssuerOID.cer           # Invalid issuer name (-114)
# rcli -y -f badCertIssuerSerNum.cer        # Invalid issuer name (-114)
# rcli -y -f badCertIssuerUtf.cer           # Invalid issuer name (-114)
# rcli -y -f badCertIssUID.cer              # Profile violation (-27)
# rcli -y -f badCertKUsageExtra.cer             # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertKUsageNoCertSign.cer        # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertKUsageNoCrit.cer        # Extension must be critical (-48)
# rcli -y -f badCertKUsageNoCRLSign.cer         # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertNoAIA.cer               # Missing AIA (-68)
# rcli -y -f badCertNoAKI.cer               # Missing AKI (-35)
# rcli -y -f badCertNoBasicConstr.cer           # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertNoCpol.cer              # Missing policy ext (-74)
# rcli -y -f badCertNoCRLDP.cer             # Missing CRLDP (-63)
# rcli -y -f badCertNoKeyUsage.cer              # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertNoSIA.cer               # Missing SIA (-71)
# rcli -y -f badCertNoSKI.cer               # Missing extension (-28)
# rcli -y -f badCertNums                    # Error reading cert (-17)
# rcli -y -f badCertOuterSigAlg.cer         # Differing algorithms in cert (-95)
# rcli -y -f badCertPubKeyAlg.cer           # Differing algorithms in cert (-95)
# rcli -y -f badCertPubKeyExp.cer           # Differing algorithms in cert (-95)
# rcli -y -f badCertPubKeyLth.cer           # Differing algorithms in cert (-95)
# rcli -y -f badCertResourcesASNoCrit.cer   # Extension must be critical (-48)
# rcli -y -f badCertResourcesBadAFI.cer     # Certificate validation error (-30)
# rcli -y -f badCertResourcesBadASOrder.cer # Invalid IP or AS numbers (-99)
# rcli -y -f badCertResourcesBadV4Order.cer # Certificate validation error (-30)
# rcli -y -f badCertResourcesBadV6Order.cer # Certificate validation error (-30)
# rcli -y -f badCertResourcesIPNoCrit.cer   # Extension must be critical (-48)
# rcli -y -f badCertResourcesNone.cer       # Missing RFC3779 ext (-78)
# rcli -y -f badCertResourcesSAFI.cer       # Certificate validation error (-30)
# rcli -y -f badCertSerNum.cer              # Bad serial number (-117)
# rcli -y -f badCertSIA2x.cer               # Duplicate SIA (-72)
# rcli -y -f badCertSIAAccessLoc.cer        # SIA not a URI (-73)
# rcli -y -f badCertSIAAccessMethod.cer     # SIA not a URI (-73)
# rcli -y -f badCertSIAMissing.cer          # Missing SIA (-71)
# rcli -y -f badCertSKIHash.cer             # Invalid SKI (-40)
# rcli -y -f badCertSKILth.cer              # Invalid SKI (-40)
# rcli -y -f badCertSubject2ComName.cer     # Invalid subject name (-113)
# rcli -y -f badCertSubject2SerNums.cer     # Invalid subject name (-113)
# rcli -y -f badCertSubject2SetComName.cer  # Invalid subject name (-113)
# rcli -y -f badCertSubjectOID.cer          # Invalid subject name (-113)
# rcli -y -f badCertSubjectSerNum.cer       # Invalid subject name (-113)
# rcli -y -f badCertSubjectUtf.cer          # Invalid subject name (-113)
# rcli -y -f badCertSubjUID.cer             # Profile violation (-27)
# rcli -y -f badCertValCrossed.cer          # Invalid dates (-94)
# rcli -y -f badCertValFromFuture.cer           # There's a possibility this should be added to the database correctly and left untouched until it becomes valid. -- David Mandelberg
# rcli -y -f badCertValFromTyp.cer          # Invalid date/time (-24)
# rcli -y -f badCertValToPast.cer           # Certificate expired (-112)
# rcli -y -f badCertValToTyp.cer            # Certificate expired (-112)
# rcli -y -f badCertVersion1.cer                # Invalid certificate flags (-46) # cg-110927:  this error result is not good
# rcli -y -f badCertVersion2.cer            # Bad certificate version (-47)
# rcli -y -f badCertVersion4.cer            # Bad certificate version (-47)
# rcli -y -f badCertVersionNeg.cer          # Bad certificate version (-47)
# rcli -y -f badCertCRLDPNoRsyncDistPt.cer  # No rsync URI in CRLDP (-116)

# ----- notes from Charlie email of Sep 27: -----
# We need a code for key usage bits to distinguish from general cert flags.
# Our testing of the public key stuff should be more specific, i.e. key size and exponent.
# SKI and Subject name tests need to be tightened up.
# The validity tests are difficult to make durable so that they test for the
#   intended error (e.g. ValCrossed) for some time to come.
