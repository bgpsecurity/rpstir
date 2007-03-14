#ifndef _Algorithms_h
#include "Algorithms.h"
#endif

void AlgorithmIdentifier(struct AlgorithmIdentifier *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    AlgorithmTableInAlgorithmIdentifier(&mine->algorithm, level);
    AlgorithmTableDefined(&mine->parameters, level);
    mine->parameters.self.flags |= ASN_OPTIONAL_FLAG;
    mine->parameters.self.flags |= ASN_LAST_FLAG;
    }

void AlgorithmTableInAlgorithmIdentifier(struct casn *mine, ushort level)
    {
    struct casn *tcasnp;
    
    memset(mine, 0, sizeof(struct casn));
    mine->tag = mine->type = ASN_OBJ_ID;
    mine->flags = ASN_TABLE_FLAG;
    mine->level = level;
    mine->ptr = (struct casn *)calloc(52, sizeof(struct casn));
    tcasnp = mine->ptr;
    tcasnp->startp = (uchar *)"1";
    tcasnp->lth = 51;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.3");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.5");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.6");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.7");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.8");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.9");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.10");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.11");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "2.16.840.1.101.2.1.1.12");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.3");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.6");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.7");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.8");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.9");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.10");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.11");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.12");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.13");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.27");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.14");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.15");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.29");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.16");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.17");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.18");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.19");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.20");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.21");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.22");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.3.2.23");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.2.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.2.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.2.5");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.1.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.1.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.1.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.3.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.3.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.3.4");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.7.2.1.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.7.2.3.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.3.14.7.2.3.2");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.10040.4.1");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.10040.4.3");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->type = ASN_OBJ_ID;
    tcasnp->lth = _write_objid(tcasnp, "1.2.840.113549.1.1.5");
    tcasnp->level = level;
    tcasnp++;
    tcasnp->lth = _write_casn(tcasnp, "\377\377", 2);
    tcasnp->level = level;
    }

void AlgorithmTableDefined(struct AlgorithmTableDefined *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    mine->self.flags |= ASN_DEFINED_FLAG;
    simple_constructor(&mine->sdnsSignatureAlgorithm, level, ASN_NONE);
    Dss_Parms(&mine->mosaicSignatureAlgorithm, level);
    mine->mosaicSignatureAlgorithm.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->sdnsConfidentialityAlgorithm, level, ASN_NONE);
    Skipjack_Parm(&mine->mosaicConfidentialityAlgorithm, level);
    mine->mosaicConfidentialityAlgorithm.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->sdnsIntegrityAlgorithm, level, ASN_NONE);
    simple_constructor(&mine->mosaicIntegrityAlgorithm, level, ASN_NONE);
    simple_constructor(&mine->sdnsTokenProtectionAlgorithm, level, ASN_NONE);
    simple_constructor(&mine->mosaicTokenProtectionAlgorithm, level, ASN_NONE);
    simple_constructor(&mine->sdnsKeyManagementAlgorithm, level, ASN_NONE);
    Kea_Parms(&mine->mosaicKeyManagementAlgorithm, level);
    mine->mosaicKeyManagementAlgorithm.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->sdnsKMandSigAlgorithms, level, ASN_NONE);
    Kea_Dss_Parms(&mine->mosaicKMandSigAlgorithms, level);
    mine->mosaicKMandSigAlgorithms.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->secsig_MD4withRSA, level, ASN_NONE);
    simple_constructor(&mine->secsig_MD5withRSA, level, ASN_NONE);
    simple_constructor(&mine->secsig_MD4withRSAEncryption, level, ASN_NULL);
    simple_constructor(&mine->secsig_DES_ECB, level, ASN_NONE);
    simple_constructor(&mine->secsig_DES_CBC, level, ASN_OCTETSTRING);
    mine->secsig_DES_CBC.flags |= ASN_OPTIONAL_FLAG;
    FBParameter(&mine->secsig_DES_OFB, level);
    mine->secsig_DES_OFB.self.flags |= ASN_OPTIONAL_FLAG;
    FBParameter(&mine->secsig_DES_CFB, level);
    mine->secsig_DES_CFB.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->secsig_DES_MAC, level, ASN_INTEGER);
    mine->secsig_DES_MAC.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->secsig_RSA, level, ASN_NONE);
    DSAParameters(&mine->secsig_DSA, level);
    mine->secsig_DSA.self.flags |= ASN_OPTIONAL_FLAG;
    DSAParameters(&mine->secsig_DSAwithSHA, level);
    mine->secsig_DSAwithSHA.self.flags |= ASN_OPTIONAL_FLAG;
    DSAParameters(&mine->secsig_DSAwithSHA_1, level);
    mine->secsig_DSAwithSHA_1.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->secsig_MDC_2withRSASignature, level, ASN_NONE);
    simple_constructor(&mine->secsig_SHAwithRSASignature, level, ASN_NONE);
    simple_constructor(&mine->secsig_SHA_1withRSASignature, level, ASN_NONE);
    simple_constructor(&mine->secsig_diffieHellman, level, ASN_NONE);
    simple_constructor(&mine->secsig_DES_EDE, level, ASN_NONE);
    simple_constructor(&mine->secsig_SHA, level, ASN_NONE);
    simple_constructor(&mine->secsig_MDC_2, level, ASN_NONE);
    simple_constructor(&mine->secsig_DSA_Common, level, ASN_NONE);
    simple_constructor(&mine->secsig_DSACommonWithSHA, level, ASN_NULL);
    mine->secsig_DSACommonWithSHA.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->secsig_MD2withRSASignature, level, ASN_NONE);
    simple_constructor(&mine->secsig_MD5withRSASignature, level, ASN_NONE);
    simple_constructor(&mine->rsadsi_MD2, level, ASN_NULL);
    simple_constructor(&mine->rsadsi_MD4, level, ASN_NULL);
    simple_constructor(&mine->rsadsi_MD5, level, ASN_NULL);
    simple_constructor(&mine->rsadsi_MD2withRSAEncryption, level, ASN_NULL);
    simple_constructor(&mine->rsadsi_MD5withRSAEncryption, level, ASN_NULL);
    simple_constructor(&mine->rsadsi_rsaEncryption, level, ASN_NULL);
    DiffieHellmanParameters(&mine->rsadsi_diffieHellman, level);
    mine->rsadsi_diffieHellman.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->rsadsi_RC2_CBC, level, ASN_NONE);
    simple_constructor(&mine->rsadsi_RC4, level, ASN_NONE);
    simple_constructor(&mine->dssig_ElGamal, level, ASN_NONE);
    simple_constructor(&mine->dssig_MD2withRSA, level, ASN_NONE);
    simple_constructor(&mine->dssig_MD2withElGamal, level, ASN_NONE);
    DSAParameters(&mine->dsa, level);
    mine->dsa.self.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->dsa_with_sha1, level, ASN_NULL);
    mine->dsa_with_sha1.flags |= ASN_OPTIONAL_FLAG;
    simple_constructor(&mine->rsadsi_SHA_1WithRSAEncryption, level, ASN_NULL);
    simple_constructor(&mine->unknown, level, ASN_ANY);
    mine->unknown.flags |= ASN_OPTIONAL_FLAG;
    mine->unknown.flags |= ASN_LAST_FLAG;
    }

void Dss_Parms(struct Dss_Parms *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->p, level, ASN_OCTETSTRING);
    simple_constructor(&mine->q, level, ASN_OCTETSTRING);
    simple_constructor(&mine->g, level, ASN_OCTETSTRING);
    mine->g.flags |= ASN_LAST_FLAG;
    }

void Kea_Parms(struct Kea_Parms *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->p, level, ASN_OCTETSTRING);
    simple_constructor(&mine->q, level, ASN_OCTETSTRING);
    simple_constructor(&mine->g, level, ASN_OCTETSTRING);
    mine->g.flags |= ASN_LAST_FLAG;
    }

void Kea_Dss_Parms(struct Kea_Dss_Parms *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_CHOICE);
    Different_Parms(&mine->diffParms, level);
    mine->diffParms.self.tag = 0xA0;
    mine->diffParms.self.flags |= ASN_EXPLICIT_FLAG;
    Common_Parms(&mine->commonParms, level);
    mine->commonParms.self.tag = 0xA1;
    mine->commonParms.self.flags |= ASN_EXPLICIT_FLAG;
    mine->commonParms.self.flags |= ASN_LAST_FLAG;
    }

void Different_Parms(struct Different_Parms *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    Kea_Parms(&mine->keaparms, level);
    Dss_Parms(&mine->dssparms, level);
    mine->dssparms.self.flags |= ASN_LAST_FLAG;
    }

void Common_Parms(struct Common_Parms *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->p, level, ASN_OCTETSTRING);
    simple_constructor(&mine->q, level, ASN_OCTETSTRING);
    simple_constructor(&mine->g, level, ASN_OCTETSTRING);
    mine->g.flags |= ASN_LAST_FLAG;
    }

void Skipjack_Parm(struct Skipjack_Parm *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->initvector, level, ASN_OCTETSTRING);
    mine->initvector.flags |= ASN_LAST_FLAG;
    }

void DiffieHellmanParameters(struct DiffieHellmanParameters *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->prime, level, ASN_INTEGER);
    simple_constructor(&mine->base, level, ASN_INTEGER);
    simple_constructor(&mine->privateValueLength, level, ASN_INTEGER);
    mine->privateValueLength.flags |= ASN_OPTIONAL_FLAG;
    mine->privateValueLength.flags |= ASN_LAST_FLAG;
    }

void DSAParameters(struct DSAParameters *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->prime1, level, ASN_INTEGER);
    simple_constructor(&mine->prime2, level, ASN_INTEGER);
    simple_constructor(&mine->base, level, ASN_INTEGER);
    mine->base.flags |= ASN_LAST_FLAG;
    }

void DSASignature(struct DSASignature *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->arr, level, ASN_INTEGER);
    simple_constructor(&mine->ess, level, ASN_INTEGER);
    mine->ess.flags |= ASN_LAST_FLAG;
    }

void FBParameter(struct FBParameter *mine, ushort level)
    {
    simple_constructor(&mine->self, level++, ASN_SEQUENCE);
    simple_constructor(&mine->iv, level, ASN_OCTETSTRING);
    simple_constructor(&mine->numberOfBits, level, ASN_INTEGER);
    mine->numberOfBits.flags |= ASN_LAST_FLAG;
    }

