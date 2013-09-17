pkglibexec_PROGRAMS += bin/rpki/chaser

bin_rpki_chaser_LDADD = \
	$(LDADD_LIBDB) \
	$(LDADD_LIBUTIL)

check_SCRIPTS += tests/subsystem/chaser/test.sh
MK_SUBST_FILES_EXEC += tests/subsystem/chaser/test.sh
tests/subsystem/chaser/test.sh: $(srcdir)/tests/subsystem/chaser/test.sh.in

TESTS += tests/subsystem/chaser/test.sh

EXTRA_DIST += \
	tests/subsystem/chaser/input.bad_chars.conf \
	tests/subsystem/chaser/input.collapse_dots.conf \
	tests/subsystem/chaser/input.collapse_slash_dot.conf \
	tests/subsystem/chaser/input.collapse_slashes.conf \
	tests/subsystem/chaser/input.max_length.conf \
	tests/subsystem/chaser/input.subsume.conf \
	tests/subsystem/chaser/response.bad_chars.log.correct \
	tests/subsystem/chaser/response.collapse_dots.log.correct \
	tests/subsystem/chaser/response.collapse_slash_dot.log.correct \
	tests/subsystem/chaser/response.collapse_slashes.log.correct \
	tests/subsystem/chaser/response.max_length.log.correct \
	tests/subsystem/chaser/response.subsume.log.correct

CLEANFILES += \
	tests/subsystem/chaser/*.diff \
	tests/subsystem/chaser/*.log


pkglibexec_PROGRAMS += bin/rpki/garbage

bin_rpki_garbage_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_SCRIPTS += bin/rpki/initialize
MK_SUBST_FILES_EXEC += bin/rpki/initialize
bin/rpki/initialize: $(srcdir)/bin/rpki/initialize.in
PACKAGE_NAME_BINS += initialize


pkglibexec_PROGRAMS += bin/rpki/query
PACKAGE_NAME_BINS += query

bin_rpki_query_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_PROGRAMS += bin/rpki/rcli

bin_rpki_rcli_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_SCRIPTS += bin/rpki/results.py
MK_SUBST_FILES_EXEC += bin/rpki/results.py
bin/rpki/results.py: $(srcdir)/bin/rpki/results.py.in


pkglibexec_SCRIPTS += bin/rpki/results
MK_SUBST_FILES_EXEC += bin/rpki/results
bin/rpki/results: $(srcdir)/bin/rpki/results.in
PACKAGE_NAME_BINS += results


pkglibexec_SCRIPTS += bin/rpki/synchronize
MK_SUBST_FILES_EXEC += bin/rpki/synchronize
bin/rpki/synchronize: $(srcdir)/bin/rpki/synchronize.in
PACKAGE_NAME_BINS += synchronize


pkglibexec_SCRIPTS += bin/rpki/updateTA.py
MK_SUBST_FILES_EXEC += bin/rpki/updateTA.py
bin/rpki/updateTA.py: $(srcdir)/bin/rpki/updateTA.py.in


pkglibexec_SCRIPTS += bin/rpki/upgrade
MK_SUBST_FILES_EXEC += bin/rpki/upgrade
bin/rpki/upgrade: $(srcdir)/bin/rpki/upgrade.in
PACKAGE_NAME_BINS += upgrade


dist_sampleta_DATA = \
	etc/sample-ta/README \
	etc/sample-ta/afrinic.tal \
	etc/sample-ta/apnic-rpki-root-afrinic-origin.tal \
	etc/sample-ta/apnic-rpki-root-arin-origin.tal \
	etc/sample-ta/apnic-rpki-root-iana-origin.tal \
	etc/sample-ta/apnic-rpki-root-lacnic-origin.tal \
	etc/sample-ta/apnic-rpki-root-ripe-origin.tal \
	etc/sample-ta/lacnic.tal \
	etc/sample-ta/ripe-ncc-root.tal

dist_conformanceta_DATA = \
	etc/sample-ta/bbn_conformance/badRootNameDiff.tal \
	etc/sample-ta/bbn_conformance/badRootBadCRLDP.tal \
	etc/sample-ta/bbn_conformance/badRootBadAKI.tal \
	etc/sample-ta/bbn_conformance/root.tal


EXTRA_DIST += tests/conformance/rfc3779

EXTRA_DIST += \
	tests/conformance/raw/badRootBadAKI.raw \
	tests/conformance/raw/badRootBadCRLDP.raw \
	tests/conformance/raw/badRootNameDiff.raw \
	tests/conformance/raw/keys/CRL2CRLNums.mft.p15 \
	tests/conformance/raw/keys/CRL2CRLNums.p15 \
	tests/conformance/raw/keys/CRLBadDate21000229.mft.p15 \
	tests/conformance/raw/keys/CRLBadDate21000229.p15 \
	tests/conformance/raw/keys/CRLBadDateDay0.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateDay0.p15 \
	tests/conformance/raw/keys/CRLBadDateDayGT30.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateDayGT30.p15 \
	tests/conformance/raw/keys/CRLBadDateDayGT31.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateDayGT31.p15 \
	tests/conformance/raw/keys/CRLBadDateFeb29.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateFeb29.p15 \
	tests/conformance/raw/keys/CRLBadDateHour.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateHour.p15 \
	tests/conformance/raw/keys/CRLBadDateMin.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateMin.p15 \
	tests/conformance/raw/keys/CRLBadDateMonth0.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateMonth0.p15 \
	tests/conformance/raw/keys/CRLBadDateMonth13.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateMonth13.p15 \
	tests/conformance/raw/keys/CRLBadDateSec.mft.p15 \
	tests/conformance/raw/keys/CRLBadDateSec.p15 \
	tests/conformance/raw/keys/CRLDeltaCRLInd.mft.p15 \
	tests/conformance/raw/keys/CRLDeltaCRLInd.p15 \
	tests/conformance/raw/keys/CRLEntryHasExtension.mft.p15 \
	tests/conformance/raw/keys/CRLEntryHasExtension.p15 \
	tests/conformance/raw/keys/CRLEntryReason.mft.p15 \
	tests/conformance/raw/keys/CRLEntryReason.p15 \
	tests/conformance/raw/keys/CRLEntrySerNumMax.mft.p15 \
	tests/conformance/raw/keys/CRLEntrySerNumMax.p15 \
	tests/conformance/raw/keys/CRLEntrySerNumTooBig.mft.p15 \
	tests/conformance/raw/keys/CRLEntrySerNumTooBig.p15 \
	tests/conformance/raw/keys/CRLIssAltName.mft.p15 \
	tests/conformance/raw/keys/CRLIssAltName.p15 \
	tests/conformance/raw/keys/CRLIssDistPt.mft.p15 \
	tests/conformance/raw/keys/CRLIssDistPt.p15 \
	tests/conformance/raw/keys/CRLIssuer2Seq.mft.p15 \
	tests/conformance/raw/keys/CRLIssuer2Seq.p15 \
	tests/conformance/raw/keys/CRLIssuer2Sets.mft.p15 \
	tests/conformance/raw/keys/CRLIssuer2Sets.p15 \
	tests/conformance/raw/keys/CRLIssuerOID.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerOID.p15 \
	tests/conformance/raw/keys/CRLIssuerSeq2SerNums.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerSeq2SerNums.p15 \
	tests/conformance/raw/keys/CRLIssuerSeqNameSer.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerSeqNameSer.p15 \
	tests/conformance/raw/keys/CRLIssuerSeqSerName.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerSeqSerName.p15 \
	tests/conformance/raw/keys/CRLIssuerSerNum.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerSerNum.p15 \
	tests/conformance/raw/keys/CRLIssuerSet2SerNums.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerSet2SerNums.p15 \
	tests/conformance/raw/keys/CRLIssuerUTF.mft.p15 \
	tests/conformance/raw/keys/CRLIssuerUTF.p15 \
	tests/conformance/raw/keys/CRLNextUpdatePast.mft.p15 \
	tests/conformance/raw/keys/CRLNextUpdatePast.p15 \
	tests/conformance/raw/keys/CRLNextUpdateTyp.mft.p15 \
	tests/conformance/raw/keys/CRLNextUpdateTyp.p15 \
	tests/conformance/raw/keys/CRLNoAKI.mft.p15 \
	tests/conformance/raw/keys/CRLNoAKI.p15 \
	tests/conformance/raw/keys/CRLNoCRLNum.mft.p15 \
	tests/conformance/raw/keys/CRLNoCRLNum.p15 \
	tests/conformance/raw/keys/CRLNoVersion.mft.p15 \
	tests/conformance/raw/keys/CRLNoVersion.p15 \
	tests/conformance/raw/keys/CRLNumber2Big.mft.p15 \
	tests/conformance/raw/keys/CRLNumber2Big.p15 \
	tests/conformance/raw/keys/CRLNumberMax.mft.p15 \
	tests/conformance/raw/keys/CRLNumberMax.p15 \
	tests/conformance/raw/keys/CRLNumberNeg.mft.p15 \
	tests/conformance/raw/keys/CRLNumberNeg.p15 \
	tests/conformance/raw/keys/CRLNumberZero.mft.p15 \
	tests/conformance/raw/keys/CRLNumberZero.p15 \
	tests/conformance/raw/keys/CRLSigAlgInner.mft.p15 \
	tests/conformance/raw/keys/CRLSigAlgInner.p15 \
	tests/conformance/raw/keys/CRLSigAlgMatchButWrong.mft.p15 \
	tests/conformance/raw/keys/CRLSigAlgMatchButWrong.p15 \
	tests/conformance/raw/keys/CRLSigAlgOuter.mft.p15 \
	tests/conformance/raw/keys/CRLSigAlgOuter.p15 \
	tests/conformance/raw/keys/CRLThisUpdateTyp.mft.p15 \
	tests/conformance/raw/keys/CRLThisUpdateTyp.p15 \
	tests/conformance/raw/keys/CRLUpdatesCrossed.mft.p15 \
	tests/conformance/raw/keys/CRLUpdatesCrossed.p15 \
	tests/conformance/raw/keys/CRLVersion0.mft.p15 \
	tests/conformance/raw/keys/CRLVersion0.p15 \
	tests/conformance/raw/keys/CRLVersion2.mft.p15 \
	tests/conformance/raw/keys/CRLVersion2.p15 \
	tests/conformance/raw/keys/MFTDuplicateFileOneHash.p15 \
	tests/conformance/raw/keys/MFTDuplicateFileTwoHashes.p15 \
	tests/conformance/raw/keys/MFTFileHashLong.p15 \
	tests/conformance/raw/keys/MFTFileHashShort.p15 \
	tests/conformance/raw/keys/MFTFileNotIA5.p15 \
	tests/conformance/raw/keys/MFTHashAlg.p15 \
	tests/conformance/raw/keys/MFTHashOctetStr.p15 \
	tests/conformance/raw/keys/MFTNegNum.p15 \
	tests/conformance/raw/keys/MFTNextUpdPast.p15 \
	tests/conformance/raw/keys/MFTNextUpdUTC.p15 \
	tests/conformance/raw/keys/MFTNoNum.p15 \
	tests/conformance/raw/keys/MFTNumMax.p15 \
	tests/conformance/raw/keys/MFTNumTooBig.p15 \
	tests/conformance/raw/keys/MFTNumZero.p15 \
	tests/conformance/raw/keys/MFTThisUpdFuture.p15 \
	tests/conformance/raw/keys/MFTThisUpdUTC.p15 \
	tests/conformance/raw/keys/MFTUnkownFileExtension.p15 \
	tests/conformance/raw/keys/MFTVersion0.p15 \
	tests/conformance/raw/keys/MFTVersion1.p15 \
	tests/conformance/raw/keys/MFTWrongType.p15 \
	tests/conformance/raw/keys/badCMS2Certs.ee.p15 \
	tests/conformance/raw/keys/badCMS2DigestAlgs.ee.p15 \
	tests/conformance/raw/keys/badCMSContentType.ee.p15 \
	tests/conformance/raw/keys/badCMSDigestAlgSameWrong.ee.p15 \
	tests/conformance/raw/keys/badCMSDigestAlgWrongOuter.ee.p15 \
	tests/conformance/raw/keys/badCMSHasCRL.ee.p15 \
	tests/conformance/raw/keys/badCMSNoCerts.ee.p15 \
	tests/conformance/raw/keys/badCMSNoDigestAlgs.ee.p15 \
	tests/conformance/raw/keys/badCMSNoSigInfo.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfo2Sig.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrs2BinSigTime.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrs2ContType.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrs2MsgDigest.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrs2SigTime.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsBinSigTime0Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsBinSigTime2Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsContType0Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsContType2Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsContTypeOid.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsMsgDigest0Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsMsgDigest2Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsNoContType.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsNoMsgDigest.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsSigTime0Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsSigTime2Val.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoAttrsWrongDigest.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoBadSid.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoBadSigVal.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoHashAlg.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoNoAttrs.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoNoHashAlg.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoNoSid.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoNoSig.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoUnSigAttrs.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoVersion.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoVersion4.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoWrongSid.ee.p15 \
	tests/conformance/raw/keys/badCMSSigInfoWrongSigAlg.ee.p15 \
	tests/conformance/raw/keys/badCMSVersion2.ee.p15 \
	tests/conformance/raw/keys/badCMSVersion4.ee.p15 \
	tests/conformance/raw/keys/badEEHasBasicConstraints.ee.p15 \
	tests/conformance/raw/keys/badEEHasCABasicConstraint.ee.p15 \
	tests/conformance/raw/keys/badEEHasEKU.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageCABits.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageHasCRLSign.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageHasKeyCertSign.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageHasKeyCertSignCABool.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageHasNonRepu.ee.p15 \
	tests/conformance/raw/keys/badEEKeyUsageNoDigitalSig.ee.p15 \
	tests/conformance/raw/keys/badEESIAExtraAccessMethod.ee.p15 \
	tests/conformance/raw/keys/badEESIAExtraWrongAccessMethod.ee.p15 \
	tests/conformance/raw/keys/badEESIANoRsync.ee.p15 \
	tests/conformance/raw/keys/badEESIAWrongAccessMethod.ee.p15 \
	tests/conformance/raw/keys/badGBRASNotInherit.ee.p15 \
	tests/conformance/raw/keys/badGBRExtraProperty.ee.p15 \
	tests/conformance/raw/keys/badGBRIPv4NotInherit.ee.p15 \
	tests/conformance/raw/keys/badGBRIPv6NotInherit.ee.p15 \
	tests/conformance/raw/keys/badGBRNoContact.ee.p15 \
	tests/conformance/raw/keys/badGBRNotVCard.ee.p15 \
	tests/conformance/raw/keys/badGBRWrongOID.ee.p15 \
	tests/conformance/raw/keys/badMFTDuplicateFileOneHash.mft.p15 \
	tests/conformance/raw/keys/badMFTDuplicateFileTwoHashes.mft.p15 \
	tests/conformance/raw/keys/badMFTFileHashLong.mft.p15 \
	tests/conformance/raw/keys/badMFTFileHashShort.mft.p15 \
	tests/conformance/raw/keys/badMFTFileNotIA5.mft.p15 \
	tests/conformance/raw/keys/badMFTHashAlg.mft.p15 \
	tests/conformance/raw/keys/badMFTHashOctetStr.mft.p15 \
	tests/conformance/raw/keys/badMFTNegNum.mft.p15 \
	tests/conformance/raw/keys/badMFTNextUpdPast.mft.p15 \
	tests/conformance/raw/keys/badMFTNextUpdUTC.mft.p15 \
	tests/conformance/raw/keys/badMFTNoNum.mft.p15 \
	tests/conformance/raw/keys/badMFTNumTooBig.mft.p15 \
	tests/conformance/raw/keys/badMFTThisUpdFuture.mft.p15 \
	tests/conformance/raw/keys/badMFTThisUpdUTC.mft.p15 \
	tests/conformance/raw/keys/badMFTVersion0.mft.p15 \
	tests/conformance/raw/keys/badMFTVersion1.mft.p15 \
	tests/conformance/raw/keys/badMFTWrongType.mft.p15 \
	tests/conformance/raw/keys/badROAASIDLarge.ee.p15 \
	tests/conformance/raw/keys/badROAASIDSmall.ee.p15 \
	tests/conformance/raw/keys/badROAFamily.ee.p15 \
	tests/conformance/raw/keys/badROAFamilyLth.ee.p15 \
	tests/conformance/raw/keys/badROAIP2Big.ee.p15 \
	tests/conformance/raw/keys/badROAIPv4DupPrefixDiffMaxLen.ee.p15 \
	tests/conformance/raw/keys/badROAIPv4DupPrefixSameMaxLen.ee.p15 \
	tests/conformance/raw/keys/badROAIPv4Inherit.ee.p15 \
	tests/conformance/raw/keys/badROAIPv4MaxLthLong.ee.p15 \
	tests/conformance/raw/keys/badROAIPv4MaxLthShort.ee.p15 \
	tests/conformance/raw/keys/badROAIPv6DupPrefixDiffMaxLen.ee.p15 \
	tests/conformance/raw/keys/badROAIPv6DupPrefixSameMaxLen.ee.p15 \
	tests/conformance/raw/keys/badROAIPv6Inherit.ee.p15 \
	tests/conformance/raw/keys/badROAIPv6LthShort.ee.p15 \
	tests/conformance/raw/keys/badROAIPv6MaxLthLong.ee.p15 \
	tests/conformance/raw/keys/badROAVersionV1Explicit.ee.p15 \
	tests/conformance/raw/keys/badROAVersionV1ExplicitBadSig.ee.p15 \
	tests/conformance/raw/keys/badROAVersionV2.ee.p15 \
	tests/conformance/raw/keys/badROAbadROAASID.ee.p15 \
	tests/conformance/raw/keys/badROAbadROAFamily.ee.p15 \
	tests/conformance/raw/keys/badROAbadROAFamilyLth.ee.p15 \
	tests/conformance/raw/keys/badROAbadROAIP2Big.ee.p15 \
	tests/conformance/raw/keys/goodEESIA2Rsync.ee.p15 \
	tests/conformance/raw/keys/goodEESIAHtRs.ee.p15 \
	tests/conformance/raw/keys/goodGBRNothingWrong.ee.p15 \
	tests/conformance/raw/keys/goodMFTNumMax.mft.p15 \
	tests/conformance/raw/keys/goodMFTNumZero.mft.p15 \
	tests/conformance/raw/keys/goodMFTUnkownFileExtension.mft.p15 \
	tests/conformance/raw/keys/goodROAASIDMax.ee.p15 \
	tests/conformance/raw/keys/goodROAASIDZero.ee.p15 \
	tests/conformance/raw/keys/goodROANothingWrong.ee.p15 \
	tests/conformance/raw/patches/badCMS2Certs.ee.stage0.patch \
	tests/conformance/raw/patches/badCMS2Certs.stage1.patch \
	tests/conformance/raw/patches/badCMS2Certs.stage2.patch \
	tests/conformance/raw/patches/badCMS2Certs.stage3.patch \
	tests/conformance/raw/patches/badCMS2DigestAlgs.ee.stage0.patch \
	tests/conformance/raw/patches/badCMS2DigestAlgs.stage1.patch \
	tests/conformance/raw/patches/badCMS2DigestAlgs.stage2.patch \
	tests/conformance/raw/patches/badCMS2DigestAlgs.stage3.patch \
	tests/conformance/raw/patches/badCMSContentType.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSContentType.stage1.patch \
	tests/conformance/raw/patches/badCMSContentType.stage2.patch \
	tests/conformance/raw/patches/badCMSContentType.stage3.patch \
	tests/conformance/raw/patches/badCMSDigestAlgSameWrong.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSDigestAlgSameWrong.stage1.patch \
	tests/conformance/raw/patches/badCMSDigestAlgSameWrong.stage2.patch \
	tests/conformance/raw/patches/badCMSDigestAlgSameWrong.stage3.patch \
	tests/conformance/raw/patches/badCMSDigestAlgWrongOuter.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSDigestAlgWrongOuter.stage1.patch \
	tests/conformance/raw/patches/badCMSDigestAlgWrongOuter.stage2.patch \
	tests/conformance/raw/patches/badCMSDigestAlgWrongOuter.stage3.patch \
	tests/conformance/raw/patches/badCMSHasCRL.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSHasCRL.stage1.patch \
	tests/conformance/raw/patches/badCMSHasCRL.stage2.patch \
	tests/conformance/raw/patches/badCMSHasCRL.stage3.patch \
	tests/conformance/raw/patches/badCMSNoCerts.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSNoCerts.stage1.patch \
	tests/conformance/raw/patches/badCMSNoCerts.stage2.patch \
	tests/conformance/raw/patches/badCMSNoCerts.stage3.patch \
	tests/conformance/raw/patches/badCMSNoDigestAlgs.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSNoDigestAlgs.stage1.patch \
	tests/conformance/raw/patches/badCMSNoDigestAlgs.stage2.patch \
	tests/conformance/raw/patches/badCMSNoDigestAlgs.stage3.patch \
	tests/conformance/raw/patches/badCMSNoSigInfo.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSNoSigInfo.stage1.patch \
	tests/conformance/raw/patches/badCMSNoSigInfo.stage2.patch \
	tests/conformance/raw/patches/badCMSNoSigInfo.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfo2Sig.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfo2Sig.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfo2Sig.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfo2Sig.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2BinSigTime.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2BinSigTime.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2BinSigTime.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2BinSigTime.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2ContType.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2ContType.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2ContType.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2ContType.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2MsgDigest.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2MsgDigest.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2MsgDigest.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2MsgDigest.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2SigTime.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2SigTime.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2SigTime.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrs2SigTime.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime0Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime0Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime0Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime0Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime2Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime2Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime2Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsBinSigTime2Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType0Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType0Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType0Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType0Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType2Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType2Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType2Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContType2Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContTypeOid.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContTypeOid.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContTypeOid.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsContTypeOid.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest0Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest0Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest0Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest0Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest2Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest2Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest2Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsMsgDigest2Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoContType.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoContType.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoContType.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoContType.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoMsgDigest.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoMsgDigest.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoMsgDigest.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsNoMsgDigest.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime0Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime0Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime0Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime0Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime2Val.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime2Val.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime2Val.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsSigTime2Val.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsWrongDigest.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsWrongDigest.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsWrongDigest.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoAttrsWrongDigest.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSid.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSid.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSid.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSid.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSigVal.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSigVal.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSigVal.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoBadSigVal.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoHashAlg.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoHashAlg.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoHashAlg.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoHashAlg.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoAttrs.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoAttrs.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoAttrs.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoAttrs.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoHashAlg.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoHashAlg.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoHashAlg.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoHashAlg.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSid.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSid.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSid.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSid.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSig.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSig.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSig.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoNoSig.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoUnSigAttrs.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoUnSigAttrs.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoUnSigAttrs.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoUnSigAttrs.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion4.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion4.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion4.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoVersion4.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSid.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSid.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSid.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSid.stage3.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSigAlg.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSigAlg.stage1.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSigAlg.stage2.patch \
	tests/conformance/raw/patches/badCMSSigInfoWrongSigAlg.stage3.patch \
	tests/conformance/raw/patches/badCMSVersion2.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSVersion2.stage1.patch \
	tests/conformance/raw/patches/badCMSVersion2.stage2.patch \
	tests/conformance/raw/patches/badCMSVersion2.stage3.patch \
	tests/conformance/raw/patches/badCMSVersion4.ee.stage0.patch \
	tests/conformance/raw/patches/badCMSVersion4.stage1.patch \
	tests/conformance/raw/patches/badCMSVersion4.stage2.patch \
	tests/conformance/raw/patches/badCMSVersion4.stage3.patch \
	tests/conformance/raw/patches/badCRL2CRLNums.stage0.patch \
	tests/conformance/raw/patches/badCRL2CRLNums.stage1.patch \
	tests/conformance/raw/patches/badCRLDeltaCRLInd.stage0.patch \
	tests/conformance/raw/patches/badCRLDeltaCRLInd.stage1.patch \
	tests/conformance/raw/patches/badCRLEntryHasExtension.stage0.patch \
	tests/conformance/raw/patches/badCRLEntryHasExtension.stage1.patch \
	tests/conformance/raw/patches/badCRLEntryReason.stage0.patch \
	tests/conformance/raw/patches/badCRLEntryReason.stage1.patch \
	tests/conformance/raw/patches/badCRLEntrySerNumTooBig.stage0.patch \
	tests/conformance/raw/patches/badCRLEntrySerNumTooBig.stage1.patch \
	tests/conformance/raw/patches/badCRLIssAltName.stage0.patch \
	tests/conformance/raw/patches/badCRLIssAltName.stage1.patch \
	tests/conformance/raw/patches/badCRLIssDistPt.stage0.patch \
	tests/conformance/raw/patches/badCRLIssDistPt.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuer2Seq.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuer2Seq.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuer2Sets.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuer2Sets.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuerOID.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuerOID.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuerSeq2SerNums.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuerSeq2SerNums.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuerSerNum.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuerSerNum.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuerSet2SerNums.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuerSet2SerNums.stage1.patch \
	tests/conformance/raw/patches/badCRLIssuerUTF.stage0.patch \
	tests/conformance/raw/patches/badCRLIssuerUTF.stage1.patch \
	tests/conformance/raw/patches/badCRLNextUpdatePast.stage0.patch \
	tests/conformance/raw/patches/badCRLNextUpdatePast.stage1.patch \
	tests/conformance/raw/patches/badCRLNextUpdateTyp.stage0.patch \
	tests/conformance/raw/patches/badCRLNextUpdateTyp.stage1.patch \
	tests/conformance/raw/patches/badCRLNoAKI.stage0.patch \
	tests/conformance/raw/patches/badCRLNoAKI.stage1.patch \
	tests/conformance/raw/patches/badCRLNoCRLNum.stage0.patch \
	tests/conformance/raw/patches/badCRLNoCRLNum.stage1.patch \
	tests/conformance/raw/patches/badCRLNoVersion.stage0.patch \
	tests/conformance/raw/patches/badCRLNoVersion.stage1.patch \
	tests/conformance/raw/patches/badCRLNumber2Big.stage0.patch \
	tests/conformance/raw/patches/badCRLNumber2Big.stage1.patch \
	tests/conformance/raw/patches/badCRLNumberNeg.stage0.patch \
	tests/conformance/raw/patches/badCRLNumberNeg.stage1.patch \
	tests/conformance/raw/patches/badCRLSigAlgInner.stage0.patch \
	tests/conformance/raw/patches/badCRLSigAlgInner.stage1.patch \
	tests/conformance/raw/patches/badCRLSigAlgMatchButWrong.stage0.patch \
	tests/conformance/raw/patches/badCRLSigAlgMatchButWrong.stage1.patch \
	tests/conformance/raw/patches/badCRLSigAlgOuter.stage0.patch \
	tests/conformance/raw/patches/badCRLSigAlgOuter.stage1.patch \
	tests/conformance/raw/patches/badCRLThisUpdateTyp.stage0.patch \
	tests/conformance/raw/patches/badCRLThisUpdateTyp.stage1.patch \
	tests/conformance/raw/patches/badCRLUpdatesCrossed.stage0.patch \
	tests/conformance/raw/patches/badCRLUpdatesCrossed.stage1.patch \
	tests/conformance/raw/patches/badCRLVersion0.stage0.patch \
	tests/conformance/raw/patches/badCRLVersion0.stage1.patch \
	tests/conformance/raw/patches/badCRLVersion2.stage0.patch \
	tests/conformance/raw/patches/badCRLVersion2.stage1.patch \
	tests/conformance/raw/patches/badCert2AKI.stage0.patch \
	tests/conformance/raw/patches/badCert2AKI.stage1.patch \
	tests/conformance/raw/patches/badCert2AKI.stage2.patch \
	tests/conformance/raw/patches/badCert2ASNum.stage0.patch \
	tests/conformance/raw/patches/badCert2ASNum.stage1.patch \
	tests/conformance/raw/patches/badCert2ASNum.stage2.patch \
	tests/conformance/raw/patches/badCert2BasicConstr.stage0.patch \
	tests/conformance/raw/patches/badCert2BasicConstr.stage1.patch \
	tests/conformance/raw/patches/badCert2BasicConstr.stage2.patch \
	tests/conformance/raw/patches/badCert2CRLDP.stage0.patch \
	tests/conformance/raw/patches/badCert2CRLDP.stage1.patch \
	tests/conformance/raw/patches/badCert2CRLDP.stage2.patch \
	tests/conformance/raw/patches/badCert2Cpol.stage0.patch \
	tests/conformance/raw/patches/badCert2Cpol.stage1.patch \
	tests/conformance/raw/patches/badCert2Cpol.stage2.patch \
	tests/conformance/raw/patches/badCert2IPAddr.stage0.patch \
	tests/conformance/raw/patches/badCert2IPAddr.stage1.patch \
	tests/conformance/raw/patches/badCert2IPAddr.stage2.patch \
	tests/conformance/raw/patches/badCert2KeyUsage.stage0.patch \
	tests/conformance/raw/patches/badCert2KeyUsage.stage1.patch \
	tests/conformance/raw/patches/badCert2KeyUsage.stage2.patch \
	tests/conformance/raw/patches/badCert2SKI.stage0.patch \
	tests/conformance/raw/patches/badCert2SKI.stage1.patch \
	tests/conformance/raw/patches/badCert2SKI.stage2.patch \
	tests/conformance/raw/patches/badCertAIA2x.stage0.patch \
	tests/conformance/raw/patches/badCertAIA2x.stage1.patch \
	tests/conformance/raw/patches/badCertAIA2x.stage2.patch \
	tests/conformance/raw/patches/badCertAIAAccessLoc.stage0.patch \
	tests/conformance/raw/patches/badCertAIAAccessLoc.stage1.patch \
	tests/conformance/raw/patches/badCertAIAAccessLoc.stage2.patch \
	tests/conformance/raw/patches/badCertAIABadAccess.stage0.patch \
	tests/conformance/raw/patches/badCertAIABadAccess.stage1.patch \
	tests/conformance/raw/patches/badCertAIABadAccess.stage2.patch \
	tests/conformance/raw/patches/badCertAIACrit.stage0.patch \
	tests/conformance/raw/patches/badCertAIACrit.stage1.patch \
	tests/conformance/raw/patches/badCertAIACrit.stage2.patch \
	tests/conformance/raw/patches/badCertAKIHasACIACSN.stage0.patch \
	tests/conformance/raw/patches/badCertAKIHasACIACSN.stage1.patch \
	tests/conformance/raw/patches/badCertAKIHasACIACSN.stage2.patch \
	tests/conformance/raw/patches/badCertAKIHash.stage0.patch \
	tests/conformance/raw/patches/badCertAKIHash.stage1.patch \
	tests/conformance/raw/patches/badCertAKIHash.stage2.patch \
	tests/conformance/raw/patches/badCertAKILong.stage0.patch \
	tests/conformance/raw/patches/badCertAKILong.stage1.patch \
	tests/conformance/raw/patches/badCertAKILong.stage2.patch \
	tests/conformance/raw/patches/badCertAKIShort.stage0.patch \
	tests/conformance/raw/patches/badCertAKIShort.stage1.patch \
	tests/conformance/raw/patches/badCertAKIShort.stage2.patch \
	tests/conformance/raw/patches/badCertBadSig.stage0.patch \
	tests/conformance/raw/patches/badCertBadSig.stage1.patch \
	tests/conformance/raw/patches/badCertBadSig.stage2.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCA.stage0.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCA.stage1.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCA.stage2.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCrit.stage0.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCrit.stage1.patch \
	tests/conformance/raw/patches/badCertBasicConstrNoCrit.stage2.patch \
	tests/conformance/raw/patches/badCertBasicConstrPathLth.stage0.patch \
	tests/conformance/raw/patches/badCertBasicConstrPathLth.stage1.patch \
	tests/conformance/raw/patches/badCertBasicConstrPathLth.stage2.patch \
	tests/conformance/raw/patches/badCertCRLDPCrit.stage0.patch \
	tests/conformance/raw/patches/badCertCRLDPCrit.stage1.patch \
	tests/conformance/raw/patches/badCertCRLDPCrit.stage2.patch \
	tests/conformance/raw/patches/badCertCRLDPCrlIssuer.stage0.patch \
	tests/conformance/raw/patches/badCertCRLDPCrlIssuer.stage1.patch \
	tests/conformance/raw/patches/badCertCRLDPCrlIssuer.stage2.patch \
	tests/conformance/raw/patches/badCertCRLDPNoRsyncDistPt.stage0.patch \
	tests/conformance/raw/patches/badCertCRLDPNoRsyncDistPt.stage1.patch \
	tests/conformance/raw/patches/badCertCRLDPNoRsyncDistPt.stage2.patch \
	tests/conformance/raw/patches/badCertCRLDPReasons.stage0.patch \
	tests/conformance/raw/patches/badCertCRLDPReasons.stage1.patch \
	tests/conformance/raw/patches/badCertCRLDPReasons.stage2.patch \
	tests/conformance/raw/patches/badCertCpol2oid1correct.stage0.patch \
	tests/conformance/raw/patches/badCertCpol2oid1correct.stage1.patch \
	tests/conformance/raw/patches/badCertCpol2oid1correct.stage2.patch \
	tests/conformance/raw/patches/badCertCpolBadOid.stage0.patch \
	tests/conformance/raw/patches/badCertCpolBadOid.stage1.patch \
	tests/conformance/raw/patches/badCertCpolBadOid.stage2.patch \
	tests/conformance/raw/patches/badCertCpolNoCrit.stage0.patch \
	tests/conformance/raw/patches/badCertCpolNoCrit.stage1.patch \
	tests/conformance/raw/patches/badCertCpolNoCrit.stage2.patch \
	tests/conformance/raw/patches/badCertEKU.stage0.patch \
	tests/conformance/raw/patches/badCertEKU.stage1.patch \
	tests/conformance/raw/patches/badCertEKU.stage2.patch \
	tests/conformance/raw/patches/badCertInnerSigAlg.stage0.patch \
	tests/conformance/raw/patches/badCertInnerSigAlg.stage1.patch \
	tests/conformance/raw/patches/badCertInnerSigAlg.stage2.patch \
	tests/conformance/raw/patches/badCertIssUID.stage0.patch \
	tests/conformance/raw/patches/badCertIssUID.stage1.patch \
	tests/conformance/raw/patches/badCertIssUID.stage2.patch \
	tests/conformance/raw/patches/badCertIssuer2ComName.stage0.patch \
	tests/conformance/raw/patches/badCertIssuer2ComName.stage1.patch \
	tests/conformance/raw/patches/badCertIssuer2ComName.stage2.patch \
	tests/conformance/raw/patches/badCertIssuer2SetComName.stage0.patch \
	tests/conformance/raw/patches/badCertIssuer2SetComName.stage1.patch \
	tests/conformance/raw/patches/badCertIssuer2SetComName.stage2.patch \
	tests/conformance/raw/patches/badCertIssuerOID.stage0.patch \
	tests/conformance/raw/patches/badCertIssuerOID.stage1.patch \
	tests/conformance/raw/patches/badCertIssuerOID.stage2.patch \
	tests/conformance/raw/patches/badCertIssuerSerNum.stage0.patch \
	tests/conformance/raw/patches/badCertIssuerSerNum.stage1.patch \
	tests/conformance/raw/patches/badCertIssuerSerNum.stage2.patch \
	tests/conformance/raw/patches/badCertIssuerSet2SerNums.stage0.patch \
	tests/conformance/raw/patches/badCertIssuerSet2SerNums.stage1.patch \
	tests/conformance/raw/patches/badCertIssuerSet2SerNums.stage2.patch \
	tests/conformance/raw/patches/badCertIssuerUtf.stage0.patch \
	tests/conformance/raw/patches/badCertIssuerUtf.stage1.patch \
	tests/conformance/raw/patches/badCertIssuerUtf.stage2.patch \
	tests/conformance/raw/patches/badCertKUsageExtra.stage0.patch \
	tests/conformance/raw/patches/badCertKUsageExtra.stage1.patch \
	tests/conformance/raw/patches/badCertKUsageExtra.stage2.patch \
	tests/conformance/raw/patches/badCertKUsageNoCRLSign.stage0.patch \
	tests/conformance/raw/patches/badCertKUsageNoCRLSign.stage1.patch \
	tests/conformance/raw/patches/badCertKUsageNoCRLSign.stage2.patch \
	tests/conformance/raw/patches/badCertKUsageNoCertSign.stage0.patch \
	tests/conformance/raw/patches/badCertKUsageNoCertSign.stage1.patch \
	tests/conformance/raw/patches/badCertKUsageNoCertSign.stage2.patch \
	tests/conformance/raw/patches/badCertKUsageNoCrit.stage0.patch \
	tests/conformance/raw/patches/badCertKUsageNoCrit.stage1.patch \
	tests/conformance/raw/patches/badCertKUsageNoCrit.stage2.patch \
	tests/conformance/raw/patches/badCertNoAIA.stage0.patch \
	tests/conformance/raw/patches/badCertNoAIA.stage1.patch \
	tests/conformance/raw/patches/badCertNoAIA.stage2.patch \
	tests/conformance/raw/patches/badCertNoAKI.stage0.patch \
	tests/conformance/raw/patches/badCertNoAKI.stage1.patch \
	tests/conformance/raw/patches/badCertNoAKI.stage2.patch \
	tests/conformance/raw/patches/badCertNoBasicConstr.stage0.patch \
	tests/conformance/raw/patches/badCertNoBasicConstr.stage1.patch \
	tests/conformance/raw/patches/badCertNoBasicConstr.stage2.patch \
	tests/conformance/raw/patches/badCertNoCRLDP.stage0.patch \
	tests/conformance/raw/patches/badCertNoCRLDP.stage1.patch \
	tests/conformance/raw/patches/badCertNoCRLDP.stage2.patch \
	tests/conformance/raw/patches/badCertNoCpol.stage0.patch \
	tests/conformance/raw/patches/badCertNoCpol.stage1.patch \
	tests/conformance/raw/patches/badCertNoCpol.stage2.patch \
	tests/conformance/raw/patches/badCertNoKeyUsage.stage0.patch \
	tests/conformance/raw/patches/badCertNoKeyUsage.stage1.patch \
	tests/conformance/raw/patches/badCertNoKeyUsage.stage2.patch \
	tests/conformance/raw/patches/badCertNoSIA.stage0.patch \
	tests/conformance/raw/patches/badCertNoSIA.stage1.patch \
	tests/conformance/raw/patches/badCertNoSIA.stage2.patch \
	tests/conformance/raw/patches/badCertNoSKI.stage0.patch \
	tests/conformance/raw/patches/badCertNoSKI.stage1.patch \
	tests/conformance/raw/patches/badCertNoSKI.stage2.patch \
	tests/conformance/raw/patches/badCertOuterSigAlg.stage0.patch \
	tests/conformance/raw/patches/badCertOuterSigAlg.stage1.patch \
	tests/conformance/raw/patches/badCertOuterSigAlg.stage2.patch \
	tests/conformance/raw/patches/badCertPubKeyAlg.stage0.patch \
	tests/conformance/raw/patches/badCertPubKeyAlg.stage1.patch \
	tests/conformance/raw/patches/badCertPubKeyAlg.stage2.patch \
	tests/conformance/raw/patches/badCertPubKeyExp.stage0.patch \
	tests/conformance/raw/patches/badCertPubKeyExp.stage1.patch \
	tests/conformance/raw/patches/badCertPubKeyExp.stage2.patch \
	tests/conformance/raw/patches/badCertPubKeyLong.stage0.patch \
	tests/conformance/raw/patches/badCertPubKeyLong.stage1.patch \
	tests/conformance/raw/patches/badCertPubKeyLong.stage2.patch \
	tests/conformance/raw/patches/badCertPubKeyShort.stage0.patch \
	tests/conformance/raw/patches/badCertPubKeyShort.stage1.patch \
	tests/conformance/raw/patches/badCertPubKeyShort.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesASEmpty.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesASEmpty.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesASEmpty.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesASNoCrit.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesASNoCrit.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesASNoCrit.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesBadAFI.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesBadAFI.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesBadAFI.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesBadASOrder.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesBadASOrder.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesBadASOrder.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesBadV4Order.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesBadV4Order.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesBadV4Order.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesBadV6Order.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesBadV6Order.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesBadV6Order.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesIPEmpty.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesIPEmpty.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesIPEmpty.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesIPNoCrit.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesIPNoCrit.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesIPNoCrit.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesNone.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesNone.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesNone.stage2.patch \
	tests/conformance/raw/patches/badCertResourcesSAFI.stage0.patch \
	tests/conformance/raw/patches/badCertResourcesSAFI.stage1.patch \
	tests/conformance/raw/patches/badCertResourcesSAFI.stage2.patch \
	tests/conformance/raw/patches/badCertSIA2x.stage0.patch \
	tests/conformance/raw/patches/badCertSIA2x.stage1.patch \
	tests/conformance/raw/patches/badCertSIA2x.stage2.patch \
	tests/conformance/raw/patches/badCertSIAAccessMethod.stage0.patch \
	tests/conformance/raw/patches/badCertSIAAccessMethod.stage1.patch \
	tests/conformance/raw/patches/badCertSIAAccessMethod.stage2.patch \
	tests/conformance/raw/patches/badCertSIAMFTNoRsync.stage0.patch \
	tests/conformance/raw/patches/badCertSIAMFTNoRsync.stage1.patch \
	tests/conformance/raw/patches/badCertSIAMFTNoRsync.stage2.patch \
	tests/conformance/raw/patches/badCertSIANoMFT.stage0.patch \
	tests/conformance/raw/patches/badCertSIANoMFT.stage1.patch \
	tests/conformance/raw/patches/badCertSIANoMFT.stage2.patch \
	tests/conformance/raw/patches/badCertSIANoRepo.stage0.patch \
	tests/conformance/raw/patches/badCertSIANoRepo.stage1.patch \
	tests/conformance/raw/patches/badCertSIANoRepo.stage2.patch \
	tests/conformance/raw/patches/badCertSIARepoNoRsync.stage0.patch \
	tests/conformance/raw/patches/badCertSIARepoNoRsync.stage1.patch \
	tests/conformance/raw/patches/badCertSIARepoNoRsync.stage2.patch \
	tests/conformance/raw/patches/badCertSKIHash.stage0.patch \
	tests/conformance/raw/patches/badCertSKIHash.stage1.patch \
	tests/conformance/raw/patches/badCertSKIHash.stage2.patch \
	tests/conformance/raw/patches/badCertSKILong.stage0.patch \
	tests/conformance/raw/patches/badCertSKILong.stage1.patch \
	tests/conformance/raw/patches/badCertSKILong.stage2.patch \
	tests/conformance/raw/patches/badCertSKIShort.stage0.patch \
	tests/conformance/raw/patches/badCertSKIShort.stage1.patch \
	tests/conformance/raw/patches/badCertSKIShort.stage2.patch \
	tests/conformance/raw/patches/badCertSerNum.stage0.patch \
	tests/conformance/raw/patches/badCertSerNum.stage1.patch \
	tests/conformance/raw/patches/badCertSerNum.stage2.patch \
	tests/conformance/raw/patches/badCertSerNum0.stage0.patch \
	tests/conformance/raw/patches/badCertSerNum0.stage1.patch \
	tests/conformance/raw/patches/badCertSerNum0.stage2.patch \
	tests/conformance/raw/patches/badCertSerNumTooBig.stage0.patch \
	tests/conformance/raw/patches/badCertSerNumTooBig.stage1.patch \
	tests/conformance/raw/patches/badCertSerNumTooBig.stage2.patch \
	tests/conformance/raw/patches/badCertSubjUID.stage0.patch \
	tests/conformance/raw/patches/badCertSubjUID.stage1.patch \
	tests/conformance/raw/patches/badCertSubjUID.stage2.patch \
	tests/conformance/raw/patches/badCertSubject2ComName.stage0.patch \
	tests/conformance/raw/patches/badCertSubject2ComName.stage1.patch \
	tests/conformance/raw/patches/badCertSubject2ComName.stage2.patch \
	tests/conformance/raw/patches/badCertSubject2SetComName.stage0.patch \
	tests/conformance/raw/patches/badCertSubject2SetComName.stage1.patch \
	tests/conformance/raw/patches/badCertSubject2SetComName.stage2.patch \
	tests/conformance/raw/patches/badCertSubjectOID.stage0.patch \
	tests/conformance/raw/patches/badCertSubjectOID.stage1.patch \
	tests/conformance/raw/patches/badCertSubjectOID.stage2.patch \
	tests/conformance/raw/patches/badCertSubjectSerNum.stage0.patch \
	tests/conformance/raw/patches/badCertSubjectSerNum.stage1.patch \
	tests/conformance/raw/patches/badCertSubjectSerNum.stage2.patch \
	tests/conformance/raw/patches/badCertSubjectSet2SerNums.stage0.patch \
	tests/conformance/raw/patches/badCertSubjectSet2SerNums.stage1.patch \
	tests/conformance/raw/patches/badCertSubjectSet2SerNums.stage2.patch \
	tests/conformance/raw/patches/badCertSubjectUtf.stage0.patch \
	tests/conformance/raw/patches/badCertSubjectUtf.stage1.patch \
	tests/conformance/raw/patches/badCertSubjectUtf.stage2.patch \
	tests/conformance/raw/patches/badCertUnkExtension.stage0.patch \
	tests/conformance/raw/patches/badCertUnkExtension.stage1.patch \
	tests/conformance/raw/patches/badCertUnkExtension.stage2.patch \
	tests/conformance/raw/patches/badCertValCrossed.stage0.patch \
	tests/conformance/raw/patches/badCertValCrossed.stage1.patch \
	tests/conformance/raw/patches/badCertValCrossed.stage2.patch \
	tests/conformance/raw/patches/badCertValFromFuture.stage0.patch \
	tests/conformance/raw/patches/badCertValFromFuture.stage1.patch \
	tests/conformance/raw/patches/badCertValFromFuture.stage2.patch \
	tests/conformance/raw/patches/badCertValFromTyp.stage0.patch \
	tests/conformance/raw/patches/badCertValFromTyp.stage1.patch \
	tests/conformance/raw/patches/badCertValFromTyp.stage2.patch \
	tests/conformance/raw/patches/badCertValToPast.stage0.patch \
	tests/conformance/raw/patches/badCertValToPast.stage1.patch \
	tests/conformance/raw/patches/badCertValToPast.stage2.patch \
	tests/conformance/raw/patches/badCertValToTyp.stage0.patch \
	tests/conformance/raw/patches/badCertValToTyp.stage1.patch \
	tests/conformance/raw/patches/badCertValToTyp.stage2.patch \
	tests/conformance/raw/patches/badCertVersion1.stage0.patch \
	tests/conformance/raw/patches/badCertVersion1.stage1.patch \
	tests/conformance/raw/patches/badCertVersion1.stage2.patch \
	tests/conformance/raw/patches/badCertVersion2.stage0.patch \
	tests/conformance/raw/patches/badCertVersion2.stage1.patch \
	tests/conformance/raw/patches/badCertVersion2.stage2.patch \
	tests/conformance/raw/patches/badCertVersion4.stage0.patch \
	tests/conformance/raw/patches/badCertVersion4.stage1.patch \
	tests/conformance/raw/patches/badCertVersion4.stage2.patch \
	tests/conformance/raw/patches/badCertVersionNeg.stage0.patch \
	tests/conformance/raw/patches/badCertVersionNeg.stage1.patch \
	tests/conformance/raw/patches/badCertVersionNeg.stage2.patch \
	tests/conformance/raw/patches/badEEHasBasicConstraints.ee.stage0.patch \
	tests/conformance/raw/patches/badEEHasBasicConstraints.stage1.patch \
	tests/conformance/raw/patches/badEEHasBasicConstraints.stage2.patch \
	tests/conformance/raw/patches/badEEHasBasicConstraints.stage3.patch \
	tests/conformance/raw/patches/badEEHasCABasicConstraint.ee.stage0.patch \
	tests/conformance/raw/patches/badEEHasCABasicConstraint.stage1.patch \
	tests/conformance/raw/patches/badEEHasCABasicConstraint.stage2.patch \
	tests/conformance/raw/patches/badEEHasCABasicConstraint.stage3.patch \
	tests/conformance/raw/patches/badEEHasEKU.ee.stage0.patch \
	tests/conformance/raw/patches/badEEHasEKU.stage1.patch \
	tests/conformance/raw/patches/badEEHasEKU.stage2.patch \
	tests/conformance/raw/patches/badEEHasEKU.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageCABits.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageCABits.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageCABits.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageCABits.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasCRLSign.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasCRLSign.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasCRLSign.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasCRLSign.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSign.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSign.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSign.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSign.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSignCABool.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSignCABool.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSignCABool.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasKeyCertSignCABool.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasNonRepu.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasNonRepu.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasNonRepu.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageHasNonRepu.stage3.patch \
	tests/conformance/raw/patches/badEEKeyUsageNoDigitalSig.ee.stage0.patch \
	tests/conformance/raw/patches/badEEKeyUsageNoDigitalSig.stage1.patch \
	tests/conformance/raw/patches/badEEKeyUsageNoDigitalSig.stage2.patch \
	tests/conformance/raw/patches/badEEKeyUsageNoDigitalSig.stage3.patch \
	tests/conformance/raw/patches/badEESIAExtraAccessMethod.ee.stage0.patch \
	tests/conformance/raw/patches/badEESIAExtraAccessMethod.stage1.patch \
	tests/conformance/raw/patches/badEESIAExtraAccessMethod.stage2.patch \
	tests/conformance/raw/patches/badEESIAExtraAccessMethod.stage3.patch \
	tests/conformance/raw/patches/badEESIAExtraWrongAccessMethod.ee.stage0.patch \
	tests/conformance/raw/patches/badEESIAExtraWrongAccessMethod.stage1.patch \
	tests/conformance/raw/patches/badEESIAExtraWrongAccessMethod.stage2.patch \
	tests/conformance/raw/patches/badEESIAExtraWrongAccessMethod.stage3.patch \
	tests/conformance/raw/patches/badEESIANoRsync.ee.stage0.patch \
	tests/conformance/raw/patches/badEESIANoRsync.stage1.patch \
	tests/conformance/raw/patches/badEESIANoRsync.stage2.patch \
	tests/conformance/raw/patches/badEESIANoRsync.stage3.patch \
	tests/conformance/raw/patches/badEESIAWrongAccessMethod.ee.stage0.patch \
	tests/conformance/raw/patches/badEESIAWrongAccessMethod.stage1.patch \
	tests/conformance/raw/patches/badEESIAWrongAccessMethod.stage2.patch \
	tests/conformance/raw/patches/badEESIAWrongAccessMethod.stage3.patch \
	tests/conformance/raw/patches/badGBRASNotInherit.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRASNotInherit.stage1.patch \
	tests/conformance/raw/patches/badGBRASNotInherit.stage2.patch \
	tests/conformance/raw/patches/badGBRASNotInherit.stage3.patch \
	tests/conformance/raw/patches/badGBRExtraProperty.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRExtraProperty.stage1.patch \
	tests/conformance/raw/patches/badGBRExtraProperty.stage2.patch \
	tests/conformance/raw/patches/badGBRExtraProperty.stage3.patch \
	tests/conformance/raw/patches/badGBRIPv4NotInherit.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRIPv4NotInherit.stage1.patch \
	tests/conformance/raw/patches/badGBRIPv4NotInherit.stage2.patch \
	tests/conformance/raw/patches/badGBRIPv4NotInherit.stage3.patch \
	tests/conformance/raw/patches/badGBRIPv6NotInherit.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRIPv6NotInherit.stage1.patch \
	tests/conformance/raw/patches/badGBRIPv6NotInherit.stage2.patch \
	tests/conformance/raw/patches/badGBRIPv6NotInherit.stage3.patch \
	tests/conformance/raw/patches/badGBRNoContact.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRNoContact.stage1.patch \
	tests/conformance/raw/patches/badGBRNoContact.stage2.patch \
	tests/conformance/raw/patches/badGBRNoContact.stage3.patch \
	tests/conformance/raw/patches/badGBRNotVCard.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRNotVCard.stage1.patch \
	tests/conformance/raw/patches/badGBRNotVCard.stage2.patch \
	tests/conformance/raw/patches/badGBRNotVCard.stage3.patch \
	tests/conformance/raw/patches/badGBRWrongOID.ee.stage0.patch \
	tests/conformance/raw/patches/badGBRWrongOID.stage1.patch \
	tests/conformance/raw/patches/badGBRWrongOID.stage2.patch \
	tests/conformance/raw/patches/badGBRWrongOID.stage3.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileOneHash.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileOneHash.stage1.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileOneHash.stage2.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileTwoHashes.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileTwoHashes.stage1.patch \
	tests/conformance/raw/patches/badMFTDuplicateFileTwoHashes.stage2.patch \
	tests/conformance/raw/patches/badMFTFileHashLong.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTFileHashLong.stage1.patch \
	tests/conformance/raw/patches/badMFTFileHashLong.stage2.patch \
	tests/conformance/raw/patches/badMFTFileHashShort.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTFileHashShort.stage1.patch \
	tests/conformance/raw/patches/badMFTFileHashShort.stage2.patch \
	tests/conformance/raw/patches/badMFTFileNotIA5.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTFileNotIA5.stage1.patch \
	tests/conformance/raw/patches/badMFTFileNotIA5.stage2.patch \
	tests/conformance/raw/patches/badMFTHashAlg.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTHashAlg.stage1.patch \
	tests/conformance/raw/patches/badMFTHashAlg.stage2.patch \
	tests/conformance/raw/patches/badMFTHashOctetStr.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTHashOctetStr.stage1.patch \
	tests/conformance/raw/patches/badMFTHashOctetStr.stage2.patch \
	tests/conformance/raw/patches/badMFTNegNum.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTNegNum.stage1.patch \
	tests/conformance/raw/patches/badMFTNegNum.stage2.patch \
	tests/conformance/raw/patches/badMFTNextUpdPast.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTNextUpdPast.stage1.patch \
	tests/conformance/raw/patches/badMFTNextUpdPast.stage2.patch \
	tests/conformance/raw/patches/badMFTNextUpdUTC.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTNextUpdUTC.stage1.patch \
	tests/conformance/raw/patches/badMFTNextUpdUTC.stage2.patch \
	tests/conformance/raw/patches/badMFTNoNum.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTNoNum.stage1.patch \
	tests/conformance/raw/patches/badMFTNoNum.stage2.patch \
	tests/conformance/raw/patches/badMFTNumTooBig.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTNumTooBig.stage1.patch \
	tests/conformance/raw/patches/badMFTNumTooBig.stage2.patch \
	tests/conformance/raw/patches/badMFTThisUpdFuture.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTThisUpdFuture.stage1.patch \
	tests/conformance/raw/patches/badMFTThisUpdFuture.stage2.patch \
	tests/conformance/raw/patches/badMFTThisUpdUTC.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTThisUpdUTC.stage1.patch \
	tests/conformance/raw/patches/badMFTThisUpdUTC.stage2.patch \
	tests/conformance/raw/patches/badMFTVersion0.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTVersion0.stage1.patch \
	tests/conformance/raw/patches/badMFTVersion0.stage2.patch \
	tests/conformance/raw/patches/badMFTVersion1.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTVersion1.stage1.patch \
	tests/conformance/raw/patches/badMFTVersion1.stage2.patch \
	tests/conformance/raw/patches/badMFTWrongType.ee.stage0.patch \
	tests/conformance/raw/patches/badMFTWrongType.stage1.patch \
	tests/conformance/raw/patches/badMFTWrongType.stage2.patch \
	tests/conformance/raw/patches/badROAASIDLarge.ee.stage0.patch \
	tests/conformance/raw/patches/badROAASIDLarge.stage1.patch \
	tests/conformance/raw/patches/badROAASIDLarge.stage2.patch \
	tests/conformance/raw/patches/badROAASIDLarge.stage3.patch \
	tests/conformance/raw/patches/badROAASIDSmall.ee.stage0.patch \
	tests/conformance/raw/patches/badROAASIDSmall.stage1.patch \
	tests/conformance/raw/patches/badROAASIDSmall.stage2.patch \
	tests/conformance/raw/patches/badROAASIDSmall.stage3.patch \
	tests/conformance/raw/patches/badROAFamily.ee.stage0.patch \
	tests/conformance/raw/patches/badROAFamily.stage1.patch \
	tests/conformance/raw/patches/badROAFamily.stage2.patch \
	tests/conformance/raw/patches/badROAFamily.stage3.patch \
	tests/conformance/raw/patches/badROAFamilyLth.ee.stage0.patch \
	tests/conformance/raw/patches/badROAFamilyLth.stage1.patch \
	tests/conformance/raw/patches/badROAFamilyLth.stage2.patch \
	tests/conformance/raw/patches/badROAFamilyLth.stage3.patch \
	tests/conformance/raw/patches/badROAIP2Big.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIP2Big.stage1.patch \
	tests/conformance/raw/patches/badROAIP2Big.stage2.patch \
	tests/conformance/raw/patches/badROAIP2Big.stage3.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixDiffMaxLen.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixDiffMaxLen.stage1.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixDiffMaxLen.stage2.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixDiffMaxLen.stage3.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixSameMaxLen.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixSameMaxLen.stage1.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixSameMaxLen.stage2.patch \
	tests/conformance/raw/patches/badROAIPv4DupPrefixSameMaxLen.stage3.patch \
	tests/conformance/raw/patches/badROAIPv4Inherit.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv4Inherit.stage1.patch \
	tests/conformance/raw/patches/badROAIPv4Inherit.stage2.patch \
	tests/conformance/raw/patches/badROAIPv4Inherit.stage3.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthLong.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthLong.stage1.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthLong.stage2.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthLong.stage3.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthShort.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthShort.stage1.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthShort.stage2.patch \
	tests/conformance/raw/patches/badROAIPv4MaxLthShort.stage3.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixDiffMaxLen.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixDiffMaxLen.stage1.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixDiffMaxLen.stage2.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixDiffMaxLen.stage3.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixSameMaxLen.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixSameMaxLen.stage1.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixSameMaxLen.stage2.patch \
	tests/conformance/raw/patches/badROAIPv6DupPrefixSameMaxLen.stage3.patch \
	tests/conformance/raw/patches/badROAIPv6Inherit.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv6Inherit.stage1.patch \
	tests/conformance/raw/patches/badROAIPv6Inherit.stage2.patch \
	tests/conformance/raw/patches/badROAIPv6Inherit.stage3.patch \
	tests/conformance/raw/patches/badROAIPv6LthShort.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv6LthShort.stage1.patch \
	tests/conformance/raw/patches/badROAIPv6LthShort.stage2.patch \
	tests/conformance/raw/patches/badROAIPv6LthShort.stage3.patch \
	tests/conformance/raw/patches/badROAIPv6MaxLthLong.ee.stage0.patch \
	tests/conformance/raw/patches/badROAIPv6MaxLthLong.stage1.patch \
	tests/conformance/raw/patches/badROAIPv6MaxLthLong.stage2.patch \
	tests/conformance/raw/patches/badROAIPv6MaxLthLong.stage3.patch \
	tests/conformance/raw/patches/badROAVersionV1Explicit.ee.stage0.patch \
	tests/conformance/raw/patches/badROAVersionV1Explicit.stage1.patch \
	tests/conformance/raw/patches/badROAVersionV1Explicit.stage2.patch \
	tests/conformance/raw/patches/badROAVersionV1Explicit.stage3.patch \
	tests/conformance/raw/patches/badROAVersionV1ExplicitBadSig.ee.stage0.patch \
	tests/conformance/raw/patches/badROAVersionV1ExplicitBadSig.stage1.patch \
	tests/conformance/raw/patches/badROAVersionV1ExplicitBadSig.stage2.patch \
	tests/conformance/raw/patches/badROAVersionV1ExplicitBadSig.stage3.patch \
	tests/conformance/raw/patches/badROAVersionV2.ee.stage0.patch \
	tests/conformance/raw/patches/badROAVersionV2.stage1.patch \
	tests/conformance/raw/patches/badROAVersionV2.stage2.patch \
	tests/conformance/raw/patches/badROAVersionV2.stage3.patch \
	tests/conformance/raw/patches/goodCRLEntrySerNumMax.stage0.patch \
	tests/conformance/raw/patches/goodCRLEntrySerNumMax.stage1.patch \
	tests/conformance/raw/patches/goodCRLIssuerSeqNameSer.stage0.patch \
	tests/conformance/raw/patches/goodCRLIssuerSeqNameSer.stage1.patch \
	tests/conformance/raw/patches/goodCRLIssuerSeqSerName.stage0.patch \
	tests/conformance/raw/patches/goodCRLIssuerSeqSerName.stage1.patch \
	tests/conformance/raw/patches/goodCRLNumberMax.stage0.patch \
	tests/conformance/raw/patches/goodCRLNumberMax.stage1.patch \
	tests/conformance/raw/patches/goodCRLNumberZero.stage0.patch \
	tests/conformance/raw/patches/goodCRLNumberZero.stage1.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescHtRs.stage0.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescHtRs.stage1.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescHtRs.stage2.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescRsRs.stage0.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescRsRs.stage1.patch \
	tests/conformance/raw/patches/goodCertAIA2AccessDescRsRs.stage2.patch \
	tests/conformance/raw/patches/goodCertCRLDP2DistPt.stage0.patch \
	tests/conformance/raw/patches/goodCertCRLDP2DistPt.stage1.patch \
	tests/conformance/raw/patches/goodCertCRLDP2DistPt.stage2.patch \
	tests/conformance/raw/patches/goodCertSIAMFT2Rsync.stage0.patch \
	tests/conformance/raw/patches/goodCertSIAMFT2Rsync.stage1.patch \
	tests/conformance/raw/patches/goodCertSIAMFT2Rsync.stage2.patch \
	tests/conformance/raw/patches/goodCertSIAMFTHtRs.stage0.patch \
	tests/conformance/raw/patches/goodCertSIAMFTHtRs.stage1.patch \
	tests/conformance/raw/patches/goodCertSIAMFTHtRs.stage2.patch \
	tests/conformance/raw/patches/goodCertSIARepo2Rsync.stage0.patch \
	tests/conformance/raw/patches/goodCertSIARepo2Rsync.stage1.patch \
	tests/conformance/raw/patches/goodCertSIARepo2Rsync.stage2.patch \
	tests/conformance/raw/patches/goodCertSIARepoHtRs.stage0.patch \
	tests/conformance/raw/patches/goodCertSIARepoHtRs.stage1.patch \
	tests/conformance/raw/patches/goodCertSIARepoHtRs.stage2.patch \
	tests/conformance/raw/patches/goodCertSerNumMax.stage0.patch \
	tests/conformance/raw/patches/goodCertSerNumMax.stage1.patch \
	tests/conformance/raw/patches/goodCertSerNumMax.stage2.patch \
	tests/conformance/raw/patches/goodEESIA2Rsync.ee.stage0.patch \
	tests/conformance/raw/patches/goodEESIA2Rsync.stage1.patch \
	tests/conformance/raw/patches/goodEESIA2Rsync.stage2.patch \
	tests/conformance/raw/patches/goodEESIA2Rsync.stage3.patch \
	tests/conformance/raw/patches/goodEESIAHtRs.ee.stage0.patch \
	tests/conformance/raw/patches/goodEESIAHtRs.stage1.patch \
	tests/conformance/raw/patches/goodEESIAHtRs.stage2.patch \
	tests/conformance/raw/patches/goodEESIAHtRs.stage3.patch \
	tests/conformance/raw/patches/goodGBRNothingWrong.ee.stage0.patch \
	tests/conformance/raw/patches/goodGBRNothingWrong.stage1.patch \
	tests/conformance/raw/patches/goodGBRNothingWrong.stage2.patch \
	tests/conformance/raw/patches/goodGBRNothingWrong.stage3.patch \
	tests/conformance/raw/patches/goodMFTNumMax.ee.stage0.patch \
	tests/conformance/raw/patches/goodMFTNumMax.stage1.patch \
	tests/conformance/raw/patches/goodMFTNumMax.stage2.patch \
	tests/conformance/raw/patches/goodMFTNumZero.ee.stage0.patch \
	tests/conformance/raw/patches/goodMFTNumZero.stage1.patch \
	tests/conformance/raw/patches/goodMFTNumZero.stage2.patch \
	tests/conformance/raw/patches/goodMFTUnkownFileExtension.ee.stage0.patch \
	tests/conformance/raw/patches/goodMFTUnkownFileExtension.stage1.patch \
	tests/conformance/raw/patches/goodMFTUnkownFileExtension.stage2.patch \
	tests/conformance/raw/patches/goodROAASIDMax.ee.stage0.patch \
	tests/conformance/raw/patches/goodROAASIDMax.stage1.patch \
	tests/conformance/raw/patches/goodROAASIDMax.stage2.patch \
	tests/conformance/raw/patches/goodROAASIDMax.stage3.patch \
	tests/conformance/raw/patches/goodROAASIDZero.ee.stage0.patch \
	tests/conformance/raw/patches/goodROAASIDZero.stage1.patch \
	tests/conformance/raw/patches/goodROAASIDZero.stage2.patch \
	tests/conformance/raw/patches/goodROAASIDZero.stage3.patch \
	tests/conformance/raw/patches/goodROANothingWrong.ee.stage0.patch \
	tests/conformance/raw/patches/goodROANothingWrong.stage1.patch \
	tests/conformance/raw/patches/goodROANothingWrong.stage2.patch \
	tests/conformance/raw/patches/goodROANothingWrong.stage3.patch \
	tests/conformance/raw/root.crl.raw \
	tests/conformance/raw/root.p15 \
	tests/conformance/raw/root.raw \
	tests/conformance/raw/templates/goodCMS.raw \
	tests/conformance/raw/templates/goodCRL.raw \
	tests/conformance/raw/templates/goodCert.p15 \
	tests/conformance/raw/templates/goodCert.raw \
	tests/conformance/raw/templates/goodEECert.p15 \
	tests/conformance/raw/templates/goodEECert.raw \
	tests/conformance/raw/templates/goodEECertGBR.raw \
	tests/conformance/raw/templates/goodGBR.raw \
	tests/conformance/raw/templates/goodROA.raw \
	tests/conformance/scripts/conformance.conf 

check_SCRIPTS += tests/conformance/scripts/gen_all.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all.sh
tests/conformance/scripts/gen_all.sh: $(srcdir)/tests/conformance/scripts/gen_all.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_CMSs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_CMSs.sh
tests/conformance/scripts/gen_all_CMSs.sh: $(srcdir)/tests/conformance/scripts/gen_all_CMSs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_CRLs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_CRLs.sh
tests/conformance/scripts/gen_all_CRLs.sh: $(srcdir)/tests/conformance/scripts/gen_all_CRLs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_GBRs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_GBRs.sh
tests/conformance/scripts/gen_all_GBRs.sh: $(srcdir)/tests/conformance/scripts/gen_all_GBRs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_MFTs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_MFTs.sh
tests/conformance/scripts/gen_all_MFTs.sh: $(srcdir)/tests/conformance/scripts/gen_all_MFTs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_ROAs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_ROAs.sh
tests/conformance/scripts/gen_all_ROAs.sh: $(srcdir)/tests/conformance/scripts/gen_all_ROAs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_certs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_certs.sh
tests/conformance/scripts/gen_all_certs.sh: $(srcdir)/tests/conformance/scripts/gen_all_certs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_child_ca.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_child_ca.sh
tests/conformance/scripts/gen_child_ca.sh: $(srcdir)/tests/conformance/scripts/gen_child_ca.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_mft.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_mft.sh
tests/conformance/scripts/gen_mft.sh: $(srcdir)/tests/conformance/scripts/gen_mft.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_CMS.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_CMS.sh
tests/conformance/scripts/make_test_CMS.sh: $(srcdir)/tests/conformance/scripts/make_test_CMS.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_CRL.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_CRL.sh
tests/conformance/scripts/make_test_CRL.sh: $(srcdir)/tests/conformance/scripts/make_test_CRL.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_MFT.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_MFT.sh
tests/conformance/scripts/make_test_MFT.sh: $(srcdir)/tests/conformance/scripts/make_test_MFT.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_cert.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_cert.sh
tests/conformance/scripts/make_test_cert.sh: $(srcdir)/tests/conformance/scripts/make_test_cert.sh.in


check_SCRIPTS += tests/conformance/scripts/run_tests.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/run_tests.sh
tests/conformance/scripts/run_tests.sh: $(srcdir)/tests/conformance/scripts/run_tests.sh.in

TESTS += \
	tests/conformance/scripts/run_tests.sh

CLEANDIRS += \
	tests/conformance/output \
	tests/conformance/raw/root

CLEANFILES += \
	tests/conformance/raw/*.cer

dist_doc_DATA += doc/conformance-cases


check_SCRIPTS += tests/subsystem/initDB
MK_SUBST_FILES_EXEC += tests/subsystem/initDB
tests/subsystem/initDB: $(srcdir)/tests/subsystem/initDB.in


check_SCRIPTS += tests/subsystem/runSubsystemTest.sh
MK_SUBST_FILES_EXEC += tests/subsystem/runSubsystemTest.sh
tests/subsystem/runSubsystemTest.sh: $(srcdir)/tests/subsystem/runSubsystemTest.sh.in


check_SCRIPTS += \
	tests/subsystem/step1.1 \
	tests/subsystem/step1.2 \
	tests/subsystem/step1.3 \
	tests/subsystem/step1.4 \
	tests/subsystem/step1.5 \
	tests/subsystem/step1.6 \
	tests/subsystem/step1.7 \
	tests/subsystem/step1.8 \
	tests/subsystem/step1.9 \
	tests/subsystem/step2.1 \
	tests/subsystem/step2.2 \
	tests/subsystem/step2.3 \
	tests/subsystem/step2.4 \
	tests/subsystem/step2.5 \
	tests/subsystem/step2.6 \
	tests/subsystem/step2.7 \
	tests/subsystem/step2.8 \
	tests/subsystem/step3.1 \
	tests/subsystem/step3.2 \
	tests/subsystem/step3.3 \
	tests/subsystem/step3.4 \
	tests/subsystem/step3.5 \
	tests/subsystem/step3.6 \
	tests/subsystem/step3.7 \
	tests/subsystem/step3.8 \
	tests/subsystem/step3.9

MK_SUBST_FILES_EXEC += \
	tests/subsystem/step1.1 \
	tests/subsystem/step1.2 \
	tests/subsystem/step1.3 \
	tests/subsystem/step1.4 \
	tests/subsystem/step1.5 \
	tests/subsystem/step1.6 \
	tests/subsystem/step1.7 \
	tests/subsystem/step1.8 \
	tests/subsystem/step1.9 \
	tests/subsystem/step2.1 \
	tests/subsystem/step2.2 \
	tests/subsystem/step2.3 \
	tests/subsystem/step2.4 \
	tests/subsystem/step2.5 \
	tests/subsystem/step2.6 \
	tests/subsystem/step2.7 \
	tests/subsystem/step2.8 \
	tests/subsystem/step3.1 \
	tests/subsystem/step3.2 \
	tests/subsystem/step3.3 \
	tests/subsystem/step3.4 \
	tests/subsystem/step3.5 \
	tests/subsystem/step3.6 \
	tests/subsystem/step3.7 \
	tests/subsystem/step3.8 \
	tests/subsystem/step3.9

tests/subsystem/step1.1: $(srcdir)/tests/subsystem/step1.1.in
tests/subsystem/step1.2: $(srcdir)/tests/subsystem/step1.2.in
tests/subsystem/step1.3: $(srcdir)/tests/subsystem/step1.3.in
tests/subsystem/step1.4: $(srcdir)/tests/subsystem/step1.4.in
tests/subsystem/step1.5: $(srcdir)/tests/subsystem/step1.5.in
tests/subsystem/step1.6: $(srcdir)/tests/subsystem/step1.6.in
tests/subsystem/step1.7: $(srcdir)/tests/subsystem/step1.7.in
tests/subsystem/step1.8: $(srcdir)/tests/subsystem/step1.8.in
tests/subsystem/step1.9: $(srcdir)/tests/subsystem/step1.9.in
tests/subsystem/step2.1: $(srcdir)/tests/subsystem/step2.1.in
tests/subsystem/step2.2: $(srcdir)/tests/subsystem/step2.2.in
tests/subsystem/step2.3: $(srcdir)/tests/subsystem/step2.3.in
tests/subsystem/step2.4: $(srcdir)/tests/subsystem/step2.4.in
tests/subsystem/step2.5: $(srcdir)/tests/subsystem/step2.5.in
tests/subsystem/step2.6: $(srcdir)/tests/subsystem/step2.6.in
tests/subsystem/step2.7: $(srcdir)/tests/subsystem/step2.7.in
tests/subsystem/step2.8: $(srcdir)/tests/subsystem/step2.8.in
tests/subsystem/step3.1: $(srcdir)/tests/subsystem/step3.1.in
tests/subsystem/step3.2: $(srcdir)/tests/subsystem/step3.2.in
tests/subsystem/step3.3: $(srcdir)/tests/subsystem/step3.3.in
tests/subsystem/step3.4: $(srcdir)/tests/subsystem/step3.4.in
tests/subsystem/step3.5: $(srcdir)/tests/subsystem/step3.5.in
tests/subsystem/step3.6: $(srcdir)/tests/subsystem/step3.6.in
tests/subsystem/step3.7: $(srcdir)/tests/subsystem/step3.7.in
tests/subsystem/step3.8: $(srcdir)/tests/subsystem/step3.8.in
tests/subsystem/step3.9: $(srcdir)/tests/subsystem/step3.9.in


check_PROGRAMS += tests/subsystem/testcases/cert_validate

tests_subsystem_testcases_cert_validate_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/testcases/gen_test_key

tests_subsystem_testcases_gen_test_key_LDADD = \
	$(LDADD_LIBUTIL)


check_PROGRAMS += tests/subsystem/testcases/make_test_cert

tests_subsystem_testcases_make_test_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_crl

tests_subsystem_testcases_make_test_crl_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_gbr

tests_subsystem_testcases_make_test_gbr_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/testcases/make_test_manifest

tests_subsystem_testcases_make_test_manifest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_roa

tests_subsystem_testcases_make_test_roa_LDADD = \
	$(LDADD_LIBRPKI)


check_SCRIPTS += tests/subsystem/testcases/tools/create_cert.py
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/tools/create_cert.py
tests/subsystem/testcases/tools/create_cert.py: $(srcdir)/tests/subsystem/testcases/tools/create_cert.py.in

check_SCRIPTS += tests/subsystem/testcases/tools/run_tc.py
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/tools/run_tc.py
tests/subsystem/testcases/tools/run_tc.py: $(srcdir)/tests/subsystem/testcases/tools/run_tc.py.in


EXTRA_DIST += \
	tests/subsystem/testcases/C.fake-parent.orig \
	tests/subsystem/testcases/C.real.orig \
	tests/subsystem/testcases/certpattern \
	tests/subsystem/testcases/falseC2.cer \
	tests/subsystem/testcases/makeC \
	tests/subsystem/testcases/makeC1 \
	tests/subsystem/testcases/makeC11 \
	tests/subsystem/testcases/makeC111 \
	tests/subsystem/testcases/makeC1111 \
	tests/subsystem/testcases/makeC112 \
	tests/subsystem/testcases/makeC113 \
	tests/subsystem/testcases/makeC12 \
	tests/subsystem/testcases/makeC121 \
	tests/subsystem/testcases/makeC13 \
	tests/subsystem/testcases/makeC131 \
	tests/subsystem/testcases/makeC132 \
	tests/subsystem/testcases/makeC2 \
	tests/subsystem/testcases/makeC21 \
	tests/subsystem/testcases/makeC211 \
	tests/subsystem/testcases/makeC22 \
	tests/subsystem/testcases/makeC221 \
	tests/subsystem/testcases/makeC2211 \
	tests/subsystem/testcases/makeC2212 \
	tests/subsystem/testcases/makeC23 \
	tests/subsystem/testcases/makeC231 \
	tests/subsystem/testcases/makeC232 \
	tests/subsystem/testcases/makeC233 \
	tests/subsystem/testcases/makeL1 \
	tests/subsystem/testcases/makeL11 \
	tests/subsystem/testcases/makeL111 \
	tests/subsystem/testcases/makeL112 \
	tests/subsystem/testcases/makeL21 \
	tests/subsystem/testcases/makeM1 \
	tests/subsystem/testcases/makeM11 \
	tests/subsystem/testcases/makeM111 \
	tests/subsystem/testcases/makeM1111 \
	tests/subsystem/testcases/makeM112 \
	tests/subsystem/testcases/makeM231 \
	tests/subsystem/testcases/queryIgnoreAll \
	tests/subsystem/testcases/t1-1_actions \
	tests/subsystem/testcases/t1-1_expect \
	tests/subsystem/testcases/t1-1_flist \
	tests/subsystem/testcases/t1-1_query \
	tests/subsystem/testcases/test1.log \
	tests/subsystem/testcases/tools/test.conf


EXTRA_DIST += \
	tests/subsystem/testcases/print-cert-addrs.sh \
	tests/subsystem/testcases/testall.sh


COPYFILES += \
	tests/subsystem/testcases/C.p15 \
	tests/subsystem/testcases/C1.p15 \
	tests/subsystem/testcases/C11.p15 \
	tests/subsystem/testcases/C111.p15 \
	tests/subsystem/testcases/C1111.p15 \
	tests/subsystem/testcases/C1111G1.p15 \
	tests/subsystem/testcases/C1111R1.p15 \
	tests/subsystem/testcases/C111M1.p15 \
	tests/subsystem/testcases/C111G1.p15 \
	tests/subsystem/testcases/C111R1.p15 \
	tests/subsystem/testcases/C111G2.p15 \
	tests/subsystem/testcases/C111R2.p15 \
	tests/subsystem/testcases/C111G3.p15 \
	tests/subsystem/testcases/C111R3.p15 \
	tests/subsystem/testcases/C112.p15 \
	tests/subsystem/testcases/C112G1.p15 \
	tests/subsystem/testcases/C112R1.p15 \
	tests/subsystem/testcases/C113.p15 \
	tests/subsystem/testcases/C113G1.p15 \
	tests/subsystem/testcases/C113R1.p15 \
	tests/subsystem/testcases/C11M1.p15 \
	tests/subsystem/testcases/C11M2.p15 \
	tests/subsystem/testcases/C11G1.p15 \
	tests/subsystem/testcases/C11R1.p15 \
	tests/subsystem/testcases/C12.p15 \
	tests/subsystem/testcases/C121.p15 \
	tests/subsystem/testcases/C121G1.p15 \
	tests/subsystem/testcases/C121R1.p15 \
	tests/subsystem/testcases/C13.p15 \
	tests/subsystem/testcases/C131.p15 \
	tests/subsystem/testcases/C131G1.p15 \
	tests/subsystem/testcases/C131R1.p15 \
	tests/subsystem/testcases/C132.p15 \
	tests/subsystem/testcases/C132G1.p15 \
	tests/subsystem/testcases/C132R1.p15 \
	tests/subsystem/testcases/C132G2.p15 \
	tests/subsystem/testcases/C132R2.p15 \
	tests/subsystem/testcases/C1M1.p15 \
	tests/subsystem/testcases/C1M2.p15 \
	tests/subsystem/testcases/C1M3.p15 \
	tests/subsystem/testcases/C2.p15 \
	tests/subsystem/testcases/C21.p15 \
	tests/subsystem/testcases/C211.p15 \
	tests/subsystem/testcases/C211G1.p15 \
	tests/subsystem/testcases/C211R1.p15 \
	tests/subsystem/testcases/C22.p15 \
	tests/subsystem/testcases/C221.p15 \
	tests/subsystem/testcases/C2211.p15 \
	tests/subsystem/testcases/C2211G1.p15 \
	tests/subsystem/testcases/C2211R1.p15 \
	tests/subsystem/testcases/C2212.p15 \
	tests/subsystem/testcases/C2212G1.p15 \
	tests/subsystem/testcases/C2212R1.p15 \
	tests/subsystem/testcases/C2212G2.p15 \
	tests/subsystem/testcases/C2212R2.p15 \
	tests/subsystem/testcases/C221G1.p15 \
	tests/subsystem/testcases/C221R1.p15 \
	tests/subsystem/testcases/C22G1.p15 \
	tests/subsystem/testcases/C22R1.p15 \
	tests/subsystem/testcases/C23.p15 \
	tests/subsystem/testcases/C231.p15 \
	tests/subsystem/testcases/C231G1.p15 \
	tests/subsystem/testcases/C231R1.p15 \
	tests/subsystem/testcases/C231G2.p15 \
	tests/subsystem/testcases/C231R2.p15 \
	tests/subsystem/testcases/C232.p15 \
	tests/subsystem/testcases/C232G1.p15 \
	tests/subsystem/testcases/C232R1.p15 \
	tests/subsystem/testcases/C233.p15 \
	tests/subsystem/testcases/C233G1.p15 \
	tests/subsystem/testcases/C233R1.p15 \
	tests/subsystem/testcases/C233G9.p15 \
	tests/subsystem/testcases/C233R9.p15 \
	tests/subsystem/testcases/C23M1.p15 \
	tests/subsystem/testcases/C23G1.p15 \
	tests/subsystem/testcases/C23R1.p15 \
	tests/subsystem/testcases/C23G2.p15 \
	tests/subsystem/testcases/C23R2.p15 \
	tests/subsystem/testcases/CM1.p15


check_SCRIPTS += tests/subsystem/testcases/makeall
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makeall
tests/subsystem/testcases/makeall: $(srcdir)/tests/subsystem/testcases/makeall.in

check_SCRIPTS += tests/subsystem/testcases/makecerts
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makecerts
tests/subsystem/testcases/makecerts: $(srcdir)/tests/subsystem/testcases/makecerts.in

check_SCRIPTS += tests/subsystem/testcases/makecrls
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makecrls
tests/subsystem/testcases/makecrls: $(srcdir)/tests/subsystem/testcases/makecrls.in

check_SCRIPTS += tests/subsystem/testcases/makegbrs
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makegbrs
tests/subsystem/testcases/makegbrs: $(srcdir)/tests/subsystem/testcases/makegbrs.in

check_SCRIPTS += tests/subsystem/testcases/makekeys
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makekeys
tests/subsystem/testcases/makekeys: $(srcdir)/tests/subsystem/testcases/makekeys.in

check_SCRIPTS += tests/subsystem/testcases/makemanifests
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makemanifests
tests/subsystem/testcases/makemanifests: $(srcdir)/tests/subsystem/testcases/makemanifests.in

check_SCRIPTS += tests/subsystem/testcases/makeroas
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/makeroas
tests/subsystem/testcases/makeroas: $(srcdir)/tests/subsystem/testcases/makeroas.in


CLEANDIRS += \
	tests/subsystem/testcases/C1 \
	tests/subsystem/testcases/C2 \
	tests/subsystem/testcases/EEcertificates

CLEANFILES += \
	tests/subsystem/testcases/*.crl \
	tests/subsystem/testcases/*.gbr \
	tests/subsystem/testcases/*.man \
	tests/subsystem/testcases/*.raw \
	tests/subsystem/testcases/*.roa \
	tests/subsystem/testcases/C*.cer



TESTS += tests/subsystem/testcases/makeall


EXTRA_DIST += \
	tests/subsystem/specs.1.2.conf \
	tests/subsystem/specs.1.3.conf \
	tests/subsystem/specs.2.6.conf \
	tests/subsystem/specs.2.8.conf \
	tests/subsystem/specs.3.3a.conf \
	tests/subsystem/specs.3.3b.conf \
	tests/subsystem/specs.3.4a.conf \
	tests/subsystem/specs.3.7.conf \
	tests/subsystem/test1.1.log \
	tests/subsystem/test1.8.log \
	tests/subsystem/test2.1.log \
	tests/subsystem/test2.7.log \
	tests/subsystem/test3.1a.log \
	tests/subsystem/test3.1b.log \
	tests/subsystem/test3.7.log


EXTRA_DIST += \
	tests/subsystem/runSubsystemTest1.sh \
	tests/subsystem/runSubsystemTest2.sh \
	tests/subsystem/runSubsystemTest3.sh


check_SCRIPTS += \
	tests/subsystem/makeC2Expired \
	tests/subsystem/makeL111Expired \
	tests/subsystem/makeM111stale

MK_SUBST_FILES_EXEC += \
	tests/subsystem/makeC2Expired \
	tests/subsystem/makeL111Expired \
	tests/subsystem/makeM111stale

tests/subsystem/makeC2Expired: $(srcdir)/tests/subsystem/makeC2Expired.in
tests/subsystem/makeL111Expired: $(srcdir)/tests/subsystem/makeL111Expired.in
tests/subsystem/makeM111stale: $(srcdir)/tests/subsystem/makeM111stale.in


CLEANFILES += \
	tests/subsystem/garbage.log \
	tests/subsystem/query.log \
	tests/subsystem/rcli.log \
	tests/subsystem/rsync_aur.log


TESTS += \
	$(srcdir)/tests/subsystem/runSubsystemTest1.sh \
	$(srcdir)/tests/subsystem/runSubsystemTest2.sh \
	$(srcdir)/tests/subsystem/runSubsystemTest3.sh
