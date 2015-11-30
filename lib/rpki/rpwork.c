#include "rpwork.h"

#include <time.h>
#include <fcntl.h>
#include "util/logging.h"
#include "rpki-object/certificate.h"
#include "util/stringutils.h"

extern struct done_certs done_certs;

static char Xvalidity_dates[40] = "";
static scm *locscmp = NULL;
static scmcon *locconp = NULL;
struct Certificate myrootcert;
char myrootfullname[PATH_MAX] = "";
struct ipranges certranges = IPRANGES_EMPTY_INITIALIZER;
struct ipranges ruleranges = IPRANGES_EMPTY_INITIALIZER;
struct ipranges lessranges = IPRANGES_EMPTY_INITIALIZER;
struct ipranges fromranges = IPRANGES_EMPTY_INITIALIZER;
char errbuf[160] = "";
char currskibuf[SKIBUFSIZ] = "";
char nextskibuf[SKIBUFSIZ] = "";
char skibuf[SKIBUFSIZ] = "";

char *Xaia = NULL;
char *Xcrldp = NULL;
char *Xcp = NULL;
char *Xrpdir = NULL;
unsigned int XrpdirId = 0;

int locflags = 0;

static void free_keyring(
    struct keyring *keyring)
{
    free(keyring->filename);
    free(keyring->label);
    free(keyring->password);
    keyring->filename = keyring->label = keyring->password = (char *)0;
}

static int add_done_cert(
    struct done_cert *tmp_done_certp)
{
    if (!done_certs.numcerts)
    {
        done_certs.done_certp =
            (struct done_cert *)calloc(1, sizeof(struct done_cert));
        done_certs.numcerts = 1;
    }
    else
        done_certs.done_certp =
            (struct done_cert *)realloc(done_certs.done_certp,
                                        (sizeof(struct done_cert) *
                                         (++done_certs.numcerts)));
    struct done_cert *done_certp =
        &done_certs.done_certp[done_certs.numcerts - 1];
    strcpy(done_certp->ski, tmp_done_certp->ski);
    done_certp->origID = tmp_done_certp->origID;
    done_certp->origflags = tmp_done_certp->origflags;
    done_certp->origcertp = tmp_done_certp->origcertp;
    done_certp->paracertp = tmp_done_certp->paracertp;
    strcpy(done_certp->filename, tmp_done_certp->filename);
    done_certp->perf = tmp_done_certp->perf;
    return done_certs.numcerts - 1;
}

static int format_aKI(
    char *namep,
    struct casn *idp)
{
    int lth = vsize_casn(idp);
    uchar *uc,
        casnbuf[64];
    read_casn(idp, casnbuf);
    char *c;
    for (uc = casnbuf, c = namep; uc < &casnbuf[lth]; c += 3)
    {
        int i;
        i = *uc++;
        sprintf(c, "%02X:", i);
    }
    *(--c) = 0;
    return (c - namep);
}

static int add_paracert2DB(
    struct done_cert *done_certp)
{
    int ansr;
    char fullname[PATH_MAX];
    char ski[80];
    ulong flags;
    struct cert_answers *cert_answersp;
    struct cert_ansr *cert_ansrp;
    unsigned int dbid;
    /** @bug ignores error code without explanation */
    ansr = findorcreatedir(locscmp, locconp, Xrpdir, &dbid);
    sprintf(fullname, "%s/%s", Xrpdir, done_certp->filename);
    /** @bug ignores error code without explanation */
    ansr = delete_object(locscmp, locconp, done_certp->filename, Xrpdir,
                         fullname, dbid);
    if (put_casn_file(&done_certp->paracertp->self, fullname, 0) < 0)
        /** @bug use a better error code */
        return ERR_SCM_UNSPECIFIED;
    ansr = add_cert(locscmp, locconp, done_certp->filename, fullname, XrpdirId,
                    0, OT_CER, &dbid, 1);
    if (ansr >= 0)
    {
        /** @bug should the SCM_FLAG_VALIDATED flag be set here? */
        flags = done_certp->origflags & ~(SCM_FLAG_NOCHAIN);
        struct Extension *extp = find_extension(
            &done_certp->paracertp->toBeSigned.extensions,
            id_subjectKeyIdentifier, 0);
        format_aKI(ski, &extp->extnValue.subjectKeyIdentifier);
        cert_answersp = find_cert_by_aKI(ski, (char *)0, locscmp, locconp);
        if (!cert_answersp || cert_answersp->num_ansrs < 0)
            /** @bug should return cert_answersp->num_ansrs */
            return ERR_SCM_UNSPECIFIED;
        int i = 0;
        for (cert_ansrp = &cert_answersp->cert_ansrp[0];
             i < cert_answersp->num_ansrs; i++, cert_ansrp++)
        {                       // if it's not a paracert, skip it
            if (!strcmp(cert_ansrp->dirname, Xrpdir))
                break;
        }
        if (i >= cert_answersp->num_ansrs)
            ansr = ERR_SCM_UNSPECIFIED;
    }
    if (ansr >= 0)
    {
        flags |= SCM_FLAG_ISPARACERT;
        flags &= ~(SCM_FLAG_HASPARACERT | SCM_FLAG_ISTARGET);
        if ((ansr = set_cert_flag(locconp, cert_ansrp->local_id, flags)) ||
            (ansr = set_cert_flag(locconp, done_certp->origID,
                                  done_certp->origflags)))
            return ansr;
        LOG(LOG_INFO, "Added %s to DB", fullname);
        return 0;
    }
    else
        /** @bug should print error string, not number */
        LOG(LOG_ERR, "Adding %s to DB failed with error %d",
                fullname, -ansr);
    return ansr;
}

static struct done_cert *have_already(
    char *ski)
{
    int i;
    for (i = 0;
         i < done_certs.numcerts && strcmp(done_certs.done_certp[i].ski, ski);
         i++);
    if (i < done_certs.numcerts)
        return &done_certs.done_certp[i];
    return (struct done_cert *)0;
}

static int snum_sfx;

static struct Certificate *mk_paracert(
    struct Certificate *origcertp,
    int flags)
{
    struct Certificate *paracertp = (struct Certificate *)calloc(
        1, sizeof(struct Certificate));
    Certificate(paracertp, (ushort) 0);
    copy_casn(&paracertp->self, &origcertp->self);
    copy_casn(&paracertp->toBeSigned.issuer.self,
              &myrootcert.toBeSigned.subject.self);
    uchar locbuf[32];
    memset(locbuf, 0, sizeof(locbuf));
    time_t now = time((time_t *) 0);
    uchar *uc;
    for (uc = &locbuf[3]; uc >= locbuf; *uc-- = (now & 0xFF), now >>= 8);
    now = ++snum_sfx;
    for (uc = &locbuf[5]; uc > &locbuf[3]; *uc-- = (now & 0xFF), now >>= 8);
    write_casn(&paracertp->toBeSigned.serialNumber, locbuf, 6);
    if (*Xvalidity_dates)
    {
        if (*Xvalidity_dates == 'C')
        {
            // do nothing
        }
        else if (*Xvalidity_dates == 'R')
            copy_casn(&paracertp->toBeSigned.validity.self,
                      &myrootcert.toBeSigned.validity.self);
        else
        {
            struct Validity *validityp = &paracertp->toBeSigned.validity;
            clear_casn(&validityp->self);
            struct casn *casnp = (Xvaliddates.lodate.type == ASN_UTCTIME) ?
                &validityp->notBefore.utcTime :
                &validityp->notBefore.generalTime;
            copy_casn(casnp, &Xvaliddates.lodate);
            casnp = (Xvaliddates.hidate.type == ASN_UTCTIME) ?
                &validityp->notAfter.utcTime :
                &validityp->notAfter.generalTime;
            copy_casn(casnp, &Xvaliddates.hidate);
        }
    }
    struct Extension *fextp,
       *textp;
    if (!Xcrldp || (*Xcrldp == 'C' && !Xcrldp[1]))
    {
        // do nothing
    }
    else if ((*Xcrldp == 'R' && !Xcrldp[1]))
    {
        fextp = find_extension(&myrootcert.toBeSigned.extensions,
                               id_cRLDistributionPoints, 0);
        textp = find_extension(&paracertp->toBeSigned.extensions,
                               id_cRLDistributionPoints, 1);
        copy_casn(&textp->self, &fextp->self);
    }
    else if (*Xcrldp != 'C' || Xcrldp[1])
    {
        textp = find_extension(&paracertp->toBeSigned.extensions,
                               id_cRLDistributionPoints, 1);
        clear_casn(&textp->extnValue.cRLDistributionPoints.self);
        write_objid(&textp->extnID, id_cRLDistributionPoints);
        char *pt,
           *ept;
        int numpts = 0;
        for (pt = Xcrldp; pt && *pt; pt = nextword(pt))
        {
            struct DistributionPoint *distp =
                (struct DistributionPoint *)inject_casn(&textp->extnValue.
                                                        cRLDistributionPoints.
                                                        self, numpts++);
            if (!distp)
            {
                xsnprintf(errbuf, sizeof(errbuf), "Too many CRLDP extensions");
                return (struct Certificate *)0;
            }
            struct GeneralName *gennamep =
                (struct GeneralName *)inject_casn(&distp->distributionPoint.
                                                  fullName.self, 0);
            if (!gennamep)
            {
                xsnprintf(errbuf, sizeof(errbuf),
                          "Too many general names in CRLDP extensions");
                return (struct Certificate *)0;
            }
            for (ept = pt; *ept > ' '; ept++);
            write_casn(&gennamep->url, (uchar *) pt, ept - pt);
        }
    }
    if (Xcp && *Xcp != 'C')
    {
        textp = find_extension(&paracertp->toBeSigned.extensions,
                               id_certificatePolicies, 1);
        if (*Xcp == 'R')
        {
            fextp = find_extension(&myrootcert.toBeSigned.extensions,
                                   id_certificatePolicies, 0);
            copy_casn(&textp->self, &fextp->self);
        }
        else
        {
            // D or specified one
            clear_casn(&textp->extnValue.self);
            write_objid(&textp->extnID, id_certificatePolicies);
            struct PolicyInformation *polInfop =
                (struct PolicyInformation *)inject_casn(&textp->extnValue.
                                                        certificatePolicies.
                                                        self, 0);
            if (*Xcp == 'D')
                write_objid(&polInfop->policyIdentifier,
                            id_pkix_rescerts_policy);
            else
                write_objid(&polInfop->policyIdentifier, Xcp);
        }
    }
    if (Xaia && *Xaia != 'C' && Xaia[0] != 0 && Xaia[1] > 0)
    {
        textp = find_extension(&paracertp->toBeSigned.extensions,
                               id_pkix_authorityInfoAccess, 1);
        clear_casn(&textp->extnValue.self);
        write_objid(&textp->extnID, id_pkix_authorityInfoAccess);
        struct AccessDescription *adp =
            (struct AccessDescription *)inject_casn(&textp->extnValue.
                                                    authorityInfoAccess.self,
                                                    0);
        write_objid(&adp->accessMethod, id_ad_caIssuers);
        write_casn(&adp->accessLocation.url, (uchar *) Xaia, strlen(Xaia));
    }
    // root's ski
    struct Extension *skiExtp;
    // new cert's aki
    struct Extension *akiExtp;
    if (!(skiExtp = find_extension(&myrootcert.toBeSigned.extensions,
                                   id_subjectKeyIdentifier, 0)))
    {
        xsnprintf(errbuf, sizeof(errbuf), "Certificate has no SKI.");
        return (struct Certificate *)0;
    }
    if (!(akiExtp = find_extension(&paracertp->toBeSigned.extensions,
                                   id_authKeyId, 0)))
    {
        if ((flags & SCM_FLAG_TRUSTED))
        {
            akiExtp =
                (struct Extension *)inject_casn(&paracertp->toBeSigned.
                                                extensions.self, 0);
            write_objid(&akiExtp->extnID, id_authKeyId);
        }
        else
        {
            xsnprintf(errbuf, sizeof(errbuf), "Certificate has no AKI.");
            return (struct Certificate *)0;
        }
    }
    copy_casn(&akiExtp->extnValue.authKeyId.keyIdentifier,
              &skiExtp->extnValue.subjectKeyIdentifier);
    mk_certranges(&certranges, paracertp);
    return paracertp;
}

static void fill_done_cert(
    struct done_cert *done_certp,
    char *cSKI,
    char *filename,
    struct Certificate *certp,
    ulong local_id,
    int flags)
{
    strcpy(done_certp->ski, cSKI);
    memset(done_certp->filename, 0, sizeof(done_certp->filename));
    strcpy(done_certp->filename, filename);
    done_certp->origcertp =
        (struct Certificate *)calloc(1, sizeof(struct Certificate));
    Certificate(done_certp->origcertp, (ushort) 0);
    copy_casn(&done_certp->origcertp->self, &certp->self);
    done_certp->origID = local_id;
    done_certp->origflags = flags;
    done_certp->paracertp = mk_paracert(certp, flags);
    done_certp->perf = 0;
}

int get_CAcert(
    char *ski,
    struct done_cert **done_certpp)
{
    struct Certificate *certp = (struct Certificate *)0;
    int i,
        j;
    struct done_cert *done_certp;
    if (ski && (done_certp = have_already(ski)))
    {
        *done_certpp = done_certp;
    }
    else
    {
        // no, get it from DB as certp
        struct cert_answers *cert_answersp =
            find_cert_by_aKI(ski, (char *)0, locscmp, locconp);
        if (!cert_answersp)
            return ERR_SCM_UNSPECIFIED;
        struct cert_ansr *cert_ansrp,
           *this_cert_ansrp;
        if (cert_answersp->num_ansrs < 0)
            return cert_answersp->num_ansrs;
        i = j = 0;
        int have_para = 0;
        for (cert_ansrp = &cert_answersp->cert_ansrp[0];
             i < cert_answersp->num_ansrs; i++, cert_ansrp++)
        {
            // if it's a paracert, note that and skip it
            if (!strcmp(cert_ansrp->dirname, Xrpdir))
            {
                have_para++;
                continue;
            }
            certp =
                (struct Certificate *)calloc(1, sizeof(struct Certificate));
            Certificate(certp, (ushort) 0);
            if (get_casn_file(&certp->self, cert_ansrp->fullname, 0) < 0)
                return ERR_SCM_COFILE;
            this_cert_ansrp = cert_ansrp;
            j++;
        }
        if (!j)
        {
            xsnprintf(errbuf, sizeof(errbuf),
                      "No CA certificate found for SKI %s\n", ski);
            return ERR_SCM_UNSPECIFIED;
        }
        else if (j > 2 || (j == 2 && !have_para))
        {
            xsnprintf(errbuf, sizeof(errbuf),
                      "Found %d certificates for SKI %s\n", j, ski);
            return ERR_SCM_UNSPECIFIED;
        }
        get_casn_file(&certp->self, this_cert_ansrp->fullname, 0);
        struct Certificate *paracertp =
            mk_paracert(certp, this_cert_ansrp->flags);
        if (!paracertp)
            return ERR_SCM_BADSKIFILE;
        else
        {
            struct done_cert done_cert;
            fill_done_cert(&done_cert, ski, this_cert_ansrp->filename, certp,
                           this_cert_ansrp->local_id, this_cert_ansrp->flags);
            int ansr = add_done_cert(&done_cert);
            done_certp = &done_certs.done_certp[ansr];
            *done_certpp = done_certp;
        }
    }
    return 0;
}

static int sign_cert(
    struct keyring *keyring,
    struct Certificate *certp)
{
    bool hashContext_initialized = false;
    CRYPT_CONTEXT hashContext;
    bool sigKeyContext_initialized = false;
    CRYPT_CONTEXT sigKeyContext;
    CRYPT_KEYSET cryptKeyset;
    uchar hash[40];
    uchar *signature = NULL;
    int ansr = 0;
    int signatureLength;
    char *msg;
    uchar *signstring = NULL;
    int sign_lth;

    if ((sign_lth = size_casn(&certp->toBeSigned.self)) < 0)
        return ERR_SCM_SIGNINGERR;
    signstring = (uchar *) calloc(1, sign_lth);
    sign_lth = encode_casn(&certp->toBeSigned.self, signstring);
    memset(hash, 0, 40);
    if (cryptInit() != CRYPT_OK)
        return ERR_SCM_CRYPTLIB;
    if ((ansr =
         cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0
        || !(hashContext_initialized = true)
        || (ansr =
            cryptCreateContext(&sigKeyContext, CRYPT_UNUSED,
                               CRYPT_ALGO_RSA)) != 0
        || !(sigKeyContext_initialized = true))
        msg = "creating context";
    else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
             (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
        msg = "hashing";
    else if ((ansr = cryptGetAttributeString(hashContext,
                                             CRYPT_CTXINFO_HASHVALUE, hash,
                                             &signatureLength)) != 0)
        msg = "getting attribute string";
    else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
                                     CRYPT_KEYSET_FILE, keyring->filename,
                                     CRYPT_KEYOPT_READONLY)) != 0)
        msg = "opening key set";
    else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext,
                                        CRYPT_KEYID_NAME, keyring->label,
                                        keyring->password)) != 0)
        msg = "getting key";
    else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength,
                                          sigKeyContext, hashContext)) != 0)
        msg = "signing";
    else
    {
        signature = (uchar *) calloc(1, signatureLength + 20);
        if ((ansr = cryptCreateSignature(signature, signatureLength + 20,
                                         &signatureLength, sigKeyContext,
                                         hashContext)) != 0)
            msg = "signing";
        else if ((ansr = cryptCheckSignature(signature, signatureLength,
                                             sigKeyContext, hashContext)) != 0)
            msg = "verifying";
    }
    if (hashContext_initialized)
    {
        cryptDestroyContext(hashContext);
        hashContext_initialized = false;
    }
    if (sigKeyContext_initialized)
    {
        cryptDestroyContext(sigKeyContext);
        sigKeyContext_initialized = false;
    }
    if (signstring)
        free(signstring);
    signstring = NULL;
    if (ansr == 0)
    {
        struct SignerInfo siginfo;
        SignerInfo(&siginfo, (ushort) 0);
        if ((ansr = decode_casn(&siginfo.self, signature)) < 0)
            msg = "decoding signature";
        else if ((ansr = readvsize_casn(&siginfo.signature, &signstring)) < 0)
            msg = "reading signature";
        else
        {
            if ((ansr =
                 write_casn_bits(&certp->signature, signstring, ansr, 0)) < 0)
                msg = "writing signature";
            else
                ansr = 0;
        }
    }
    if (signstring != NULL)
        free(signstring);
    if (signature != NULL)
        free(signature);
    if (ansr)
    {
        xsnprintf(errbuf, sizeof(errbuf), "Error %s\n", msg);
        fflush(stderr);
        return ERR_SCM_SIGNINGERR;
    }
    return 0;
}

static void save_cert_answers(
    struct cert_answers *to_cert_answersp,
    struct cert_answers *from_cert_answersp)
{
    int numkid;
    int numkids = from_cert_answersp->num_ansrs;
    to_cert_answersp->num_ansrs = numkids;
    /**
     * @bug
     *     ignores error code without explanation (numkids might be
     *     negative)
     */
    to_cert_answersp->cert_ansrp =
        (struct cert_ansr *)calloc(numkids, sizeof(struct cert_ansr));
    for (numkid = 0; numkid < numkids; numkid++)
    {
        /** @bug possible null pointer dereference if calloc() failed */
        to_cert_answersp->cert_ansrp[numkid] =
            from_cert_answersp->cert_ansrp[numkid];
    }
}


static void make_ASnum(
    struct ASNumberOrRangeA *asNumberOrRangep,
    struct iprange *iprangep)
{
    int asnum;
    uchar *u,
       *e;

    for (asnum = 0, u = iprangep->lolim, e = &u[4]; u < e; u++)
    {
        asnum <<= 8;
        asnum += *u;
    }
    if (memcmp(iprangep->lolim, iprangep->hilim, 4) == 0)
        write_casn_num(&asNumberOrRangep->num, asnum);
    else
    {
        write_casn_num(&asNumberOrRangep->range.min, asnum);
        for (asnum = 0, u = iprangep->hilim, e = &u[4]; u < e; u++)
        {
            asnum <<= 8;
            asnum += *u;
        }
        write_casn_num(&asNumberOrRangep->range.max, asnum);
    }
}

static int expand(
    struct ipranges *rulerangesp,
    int numrulerange,
    struct ipranges *certrangesp,
    int numcertrange,
    int *changesp)
{
    /*
     * 1. WHILE have rule
     *      IF have C, test R-hi touching C-lo
     * 2.   IF have no C OR R-hi < C-lo
     *        Inject new C
     *        Set C-lo to R-lo
     *        Set C-hi to R-hi
     *        Get next rule
     * 3.   ELSE IF R-hi just touches C-lo
     *        Set C-lo to R-lo
     *        IF C-hi >= R-hi, finished with this rule so get next rule
     * 4.   ELSE ( R-hi > C-lo)
     *        IF C-hi doesn't touch R-lo
     *          Get next C
     *          Continue in WHILE
     *        IF C-lo > R-lo, set C-lo to R-lo
     *        IF R-hi > C-hi,
     *          Set C-hi to R-hi
     *          Get next rule
     *      IF no rule, break out of WHILE
     * 5.   Do C-hi
     *      IF R-hi <= C-hi
     *        Get next rule
     *      ELSE (R-hi > C-hi)
     *        IF C-hi touches R-lo, set C-hi to R-hi
     *        ELSE get next C
     */
    int did = 0;
    struct iprange *certrangep = &certrangesp->iprangep[numcertrange];
    struct iprange *rulerangep = &rulerangesp->iprangep[numrulerange];
    int lth = rulerangep->typ == IPv6 ? 16 : 4;
    int flag = 0;
    int lastcert = numcertrange - 1;
    if ((locflags & RESOURCE_NOUNION))
        flag = 1;
    // step 1
    while (rulerangep)
    {
        int ansr = -1;
        if (certrangep)
            ansr = touches(rulerangep, certrangep, lth);
        // step 2
        if (ansr < 0)
        {
            if (flag)
                return ERR_SCM_UNSPECIFIED;
            certrangep = inject_range(certrangesp, ++lastcert);
            certrangep->typ = rulerangep->typ;
            memcpy(certrangep->lolim, rulerangep->lolim, lth);
            memcpy(certrangep->hilim, rulerangep->hilim, lth);
            rulerangep = next_range(rulerangesp, rulerangep);
            did++;
            if (!rulerangep)
                continue;
        }
        // step 3
        else if (!ansr)
        {
            if (flag)
                return ERR_SCM_UNSPECIFIED;
            memcpy(certrangep->lolim, rulerangep->lolim, lth);
            if (memcmp(certrangep->hilim, rulerangep->hilim, lth) >= 0)
                rulerangep = next_range(rulerangesp, rulerangep);
            did++;
        }
        // ansr > 0 step 4
        else
        {
            if (touches(certrangep, rulerangep, lth) < 0)
            {
                lastcert = certrangep - certranges.iprangep;
                certrangep = next_range(certrangesp, certrangep);
                continue;
            }
            if (memcmp(certrangep->lolim, rulerangep->lolim, lth) > 0)
            {
                if (flag)
                    return ERR_SCM_UNSPECIFIED;
                memcpy(certrangep->lolim, rulerangep->lolim, lth);
                did++;
            }
            if (memcmp(rulerangep->hilim, certrangep->hilim, lth) > 0)
            {
                if (flag)
                    return ERR_SCM_UNSPECIFIED;
                memcpy(certrangep->hilim, rulerangep->hilim, lth);
                rulerangep = next_range(rulerangesp, rulerangep);
                did++;
            }
        }
        if (!rulerangep)
            break;
        // step 5
        if (memcmp(rulerangep->hilim, certrangep->hilim, lth) <= 0)
        {
            rulerangep = next_range(rulerangesp, rulerangep);
            did++;
        }
        else if ((ansr = touches(certrangep, rulerangep, lth)) >= 0)
        {
            if (flag)
                return ERR_SCM_UNSPECIFIED;
            memcpy(certrangep->hilim, rulerangep->hilim, lth);
            lastcert = certrangep - certrangesp->iprangep;
            certrangep = next_range(certrangesp, certrangep);
            rulerangep = next_range(rulerangesp, rulerangep);
        }
        else
        {
            lastcert = certrangep - certrangesp->iprangep;
            certrangep = next_range(certrangesp, certrangep);
        }
    }
    *changesp += did;
    return did;
}

static int perforate(
    struct ipranges *rulerangesp,
    int numrulerange,
    struct ipranges *certrangesp,
    int numcertrange,
    int *changesp)
{
    // result = certranges - ruleranges
    /*
     * Procedure:
     *    Starting at first rule (one guaranteed) and first cert field of this
     *      type (not guaranteed)
     * Notation: C is certificate item, C-lo is its low end, C-hi its high end
     *           R is rule item, R-lo is its low end, R-hi its high end
     * 1. WHILE have C AND have R of this type
     *     IF C-hi < R-lo
     *       Get next C
     *       Start WHILE again
     *     IF C-lo > R-hi
     *       Get next R
     *       Start WHILE again
     *     Now C-lo <= R-hi AND C-hi >= R-lo
     * 2.  IF C-lo < R-lo
     *         IF C-hi <= R-hi
     *           Set C-hi = R-lo - 1.
     *           Get next cert
     *         ELSE (C-hi > R-hi)
     *             Inject new C with C-lo = old C-lo AND C-hi = R-lo - 1
     *             Go to next C
     *             Set C-lo to R-hi + 1
     *             Get next R
     * 3.  ELSE (C-lo >= R-lo)
     *         IF C-hi <= R-hi, delete C
     *         ELSE (C-hi > R-hi) chop off low end of C
     *             Set C-lo = R-hi + 1
     *             Get next R
     *   Return index of last rule
     */
    struct iprange *certrangep = &certrangesp->iprangep[numcertrange];
    struct iprange *rulerangep = &rulerangesp->iprangep[numrulerange];
    int did = 0;
    int typ = certrangep->typ;
    int lth = (typ == IPv6) ? 16 : 4;
    // step 1
    while (certrangep && rulerangep)
    {
        if (memcmp(certrangep->hilim, rulerangep->lolim, lth) < 0)
        {
            certrangep = next_range(certrangesp, certrangep);
            continue;
        }
        if (memcmp(certrangep->lolim, rulerangep->hilim, lth) > 0)
        {
            rulerangep = next_range(rulerangesp, rulerangep);
            continue;
        }
        // step 2
        if (memcmp(certrangep->lolim, rulerangep->lolim, lth) < 0)
        {
            if (memcmp(certrangep->hilim, rulerangep->hilim, lth) <= 0)
            {
                // C-hi <= R-hi
                memcpy(certrangep->hilim, rulerangep->lolim, lth);
                decrement_iprange(certrangep->hilim, lth);
                certrangep = next_range(certrangesp, certrangep);
            }
            else
            {
                // C-hi > R-hi
                certrangep = inject_range(certrangesp,
                                          certrangep - certrangesp->iprangep);
                memcpy(certrangep->lolim, certrangep[1].lolim, lth);
                memcpy(certrangep->hilim, rulerangep->lolim, lth);
                certrangep->typ = certrangep[1].typ;
                decrement_iprange(certrangep->hilim, lth);
                certrangep++;
                memcpy(certrangep->lolim, rulerangep->hilim, lth);
                increment_iprange(certrangep->lolim, lth);
                rulerangep = next_range(rulerangesp, rulerangep);
            }
            did++;
        }
        // step 3
        else
        {
            // C-lo >= R-lo
            if (memcmp(certrangep->hilim, rulerangep->hilim, lth) <= 0)
                certrangep = eject_range(certrangesp, certrangep -
                                         certrangesp->iprangep);
            else
            {
                // C-hi > R-hi
                memcpy(certrangep->lolim, rulerangep->hilim, lth);
                increment_iprange(certrangep->lolim, lth);
                rulerangep = next_range(rulerangesp, rulerangep);
            }
            did++;
        }
    }
    *changesp += did;
    return did;
}

static int perf_A_from_B(
    struct ipranges *lessp,
    struct ipranges *fromp)
{
    int ansr;
    int typ = IPv4;
    int lessnum = 0;
    int fromnum = 0;
    int changes = 0;
    if ((ansr = perforate(lessp, lessnum, fromp, fromnum, &changes)) < 0)
        return ansr;
    for (lessnum = 0; lessnum < lessp->numranges - 1 &&
         lessp->iprangep[lessnum].typ <= typ; lessnum++);
    for (fromnum = 0; fromnum < fromp->numranges - 1 &&
         fromp->iprangep[fromnum].typ <= typ; fromnum++);
    typ = IPv6;
    if (fromp->iprangep[fromnum].typ == typ &&
        lessp->iprangep[lessnum].typ == typ &&
        (ansr = perforate(lessp, lessnum, fromp, fromnum, &changes)) < 0)
        return ansr;
    for (lessnum = 0; lessnum < lessp->numranges - 1 &&
         lessp->iprangep[lessnum].typ <= typ; lessnum++);
    for (fromnum = 0; fromnum < fromp->numranges - 1 &&
         fromp->iprangep[fromnum].typ <= typ; fromnum++);
    typ = ASNUM;
    if (fromp->iprangep[fromnum].typ == typ &&
        lessp->iprangep[lessnum].typ == typ)
        ansr = perforate(lessp, lessnum, fromp, fromnum, &changes);
    return ansr;
}

static void copy_text(
    struct iprange *rulep,
    struct iprange *savp)
{
    if (memcmp(rulep->lolim, savp->lolim, 16) <= 0 &&
        memcmp(rulep->hilim, savp->hilim, 16) >= 0)
    {
        savp->text = calloc(1, strlen(rulep->text) + 2);
        strcat(strcat(skibuf, rulep->text), " ");
    }
}

static int conflict_test(
    int perf,
    struct done_cert *done_certp)
{
    /*
     * 1. IF have done perforation and are now expanding (orig > para)
     *      Make fromrange out of origcert
     *      Make lessrange out of paracert
     *    ELSE have expanded and are nor perforating
     *      Make fromrange out of paracert
     *      Make lessrange out of origcert
     * 2. Perforate fromrange with lessrange
     * 3. Compare resulting fromrange with original rule list
     *    IF there is any overlap, error
     *    ELSE no error
     */
    int ansr;
    if (!perf)                  // step 1
    {
        mk_certranges(&fromranges, done_certp->origcertp);
        mk_certranges(&lessranges, done_certp->paracertp);
    }
    else
    {
        mk_certranges(&fromranges, done_certp->paracertp);
        mk_certranges(&lessranges, done_certp->origcertp);
    }
    // step 2
    if ((ansr = perf_A_from_B(&lessranges, &fromranges)) < 0)
        return ansr;
    // step 3
    clear_ipranges(&lessranges);
    struct iprange *iprangep;
    int i;                      // copy rules to less
    for (i = 0; i < ruleranges.numranges; i++)
    {
        struct iprange *rulerangep = &ruleranges.iprangep[i];
        iprangep = inject_range(&lessranges, i);
        iprangep->typ = ruleranges.iprangep[i].typ;
        memcpy(iprangep->lolim, rulerangep->lolim, sizeof(iprangep->lolim));
        memcpy(iprangep->hilim, rulerangep->hilim, sizeof(iprangep->hilim));
        if (rulerangep->text)
        {
            iprangep->text = calloc(1, strlen(rulerangep->text));
            strcpy(iprangep->text, rulerangep->text);
        }
    }
    iprangep = inject_range(&lessranges, i);
    iprangep->typ = 0;
    memset(iprangep->lolim, 0, sizeof(iprangep->lolim));
    memset(iprangep->hilim, 0, sizeof(iprangep->hilim));
    struct ipranges savranges;  // save copy of fromrange
    savranges.numranges = 0;
    savranges.iprangep = (struct iprange *)0;
    int j;
    // save the present fromranges
    for (j = 0; j < fromranges.numranges; j++)
    {
        struct iprange *siprangep;
        struct iprange *fiprangep;
        inject_range(&savranges, j);
        siprangep = &savranges.iprangep[j];
        fiprangep = &fromranges.iprangep[j];
        siprangep->typ = fiprangep->typ;
        memcpy(siprangep->lolim, fiprangep->lolim, sizeof(fiprangep->lolim));
        memcpy(siprangep->hilim, fiprangep->hilim, sizeof(fiprangep->hilim));
    }
    ansr = perf_A_from_B(&lessranges, &fromranges);
    if (ansr < 0)
        return ansr;
    if (fromranges.numranges > 1)
    {
        // "subtract" new fromranges from old

        // diff shows where it occurred
        /** @bug ignores error code without explanation */
        perf_A_from_B(&fromranges, &savranges);
        // find where
        int jj;
        int k = 0;
        *skibuf = 0;
        struct iprange *savp;
        for (jj = 0; jj < savranges.numranges; jj++)
        {
            int kk;
            savp = &savranges.iprangep[jj];
            if (savp->typ == IPv4)
            {
                for (kk = 0; ruleranges.iprangep[kk].typ == IPv4; kk++)
                {
                    copy_text(&ruleranges.iprangep[kk], savp);
                }
                k++;
                while (savranges.iprangep[jj].typ == IPv4)
                    jj++;
            }
            else if (savranges.iprangep[jj].typ == IPv6)
            {
                for (kk = 0; ruleranges.iprangep[kk].typ == IPv6; kk++)
                {
                    copy_text(&ruleranges.iprangep[kk], savp);
                }
                while (savranges.iprangep[jj].typ == IPv6)
                    jj++;
            }
            else if (savranges.iprangep[jj].typ == ASNUM)
            {
                for (kk = 0; ruleranges.iprangep[kk].typ == IPv4; kk++)
                {
                    copy_text(&ruleranges.iprangep[kk], savp);
                }
                while (savranges.iprangep[jj].typ == ASNUM)
                    jj++;
            }
        }
        ansr = 1;
    }
    else
        ansr = 0;
    free_ipranges(&fromranges);
    free_ipranges(&lessranges);
    return ansr;
}

/*
 * Function: Reads through list of addresses and cert extensions to expand
 * or perforate them.
 * inputs:  run: 0 = expand, 1 = perforate,
 *         index to first iprange of this typ.  At least one guaranteed
 *         index "   " certrange "   "    " .  Not guaranteed
 *         Ptr to record changes
 * Returns: Index to next constraint beyond this type
 * Procedure:
 * 1. IF expanding, expand cert
 *    ELSE IF have certificate items of this type, perforate them
 *    Reconstruct IP addresses in cert from ruleranges
 *    Note ending point in list
 */
static int run_through_typlist(
    int run,
    int numrulerange,
    int numcertrange,
    int *changesp)
{
    int did;
    // step 1
    if (!run)
    {
        did = expand(&ruleranges, numrulerange, &certranges, numcertrange,
                     changesp);
        if (did < 0)
        {
            char *typname;
            if (ruleranges.iprangep[numrulerange].typ == IPv4)
                typname = "IPv4";
            else if (ruleranges.iprangep[numrulerange].typ == IPv6)
                typname = "IPv6";
            else
                typname = "AS#";
            LOG(LOG_DEBUG, "Did not expand %s in block %s.", typname,
                    currskibuf);
            did = 0;
        }
    }
    else
        did = perforate(&ruleranges, numrulerange, &certranges, numcertrange,
                        changesp);
    return did;
}

static void remake_cert_ranges(
    struct Certificate *paracertp)
{
    /*
     * Function: reconstructs extensions in paracert from (modified?)
     * certranges
     * Procedure:
     * 1. IF have an extension for IP addresses, empty it
     * 2. IF have certranges for IPv4
     *      IF no such extension, add one
     *      Translate all IPv4 addresses in certrange to the cert's IPv4 space
     * 3. IF have any ranges for IPv6
     *      IF no such extension, add one
     *      Translate all IPv6 addresses in certrange to the cert's IPv6 space
     * 4. IF cert has an AS# extension, empty it
     *    IF have any ranges for AS#
     *      IF no such extension, add one
     *      Translate all AS numbers in certrange to the cert's AS number space
     */
    struct iprange *certrangep = certranges.iprangep;
    int num4 = 0,
        num6 = 0;
    struct Extension *extp = find_extension(
        &paracertp->toBeSigned.extensions, id_pe_ipAddrBlock, 0);
    struct Extensions *extsp = &paracertp->toBeSigned.extensions;
    struct IpAddrBlock *ipAddrBlockp;
    struct IPAddressFamilyA *ipfamp;
    struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp = NULL;
    struct IPAddressOrRangeA *ipAddrOrRangep;
    int numfam = 0;
    uchar fambuf[2];
    // step 1
    *fambuf = 0;
    if (extp)
    {
        int i;
        for (i = num_items(&extp->extnValue.ipAddressBlock.self); i > 0;
             eject_casn(&extp->extnValue.ipAddressBlock.self, --i));
    }
    if (certrangep->typ == IPv4)        // step 2
    {
        if (!extp)
        {
            // at the end of extensions
            extp = (struct Extension *)inject_casn(&extsp->self,
                                                   num_items(&extsp->self));
        }
        // rewrite objid because step 1 cleared it
        write_objid(&extp->extnID, id_pe_ipAddrBlock);
        ipAddrBlockp = &extp->extnValue.ipAddressBlock;
        ipfamp = (struct IPAddressFamilyA *)inject_casn(&ipAddrBlockp->self,
                                                        numfam++);
        fambuf[1] = 1;
        write_casn(&ipfamp->addressFamily, fambuf, 2);
        ipAddrOrRangesp = &ipfamp->ipAddressChoice.addressesOrRanges;
        for (certrangep = certranges.iprangep; certrangep;
             certrangep = next_range(&certranges, certrangep), num4++)
        {
            ipAddrOrRangep =
                (struct IPAddressOrRangeA *)inject_casn(&ipAddrOrRangesp->self,
                                                        num4);
            make_IPAddrOrRange(ipAddrOrRangep,
                               certrangep->typ == IPv4 ? AF_INET : AF_INET6,
                               certrangep->lolim,
                               certrangep->hilim);
        }
    }
    // step 3
    if ((certrangep = &certranges.iprangep[num4])->typ == IPv6)
    {
        if (!extp)
        {
            // at the end of extensions
            extp = (struct Extension *)inject_casn(&extsp->self,
                                                   num_items(&extsp->self));
        }
        ipAddrBlockp = &extp->extnValue.ipAddressBlock;
        ipfamp = (struct IPAddressFamilyA *)inject_casn(&ipAddrBlockp->self,
                                                        numfam++);
        fambuf[1] = 2;
        write_casn(&ipfamp->addressFamily, fambuf, 2);
        ipAddrOrRangesp = &ipfamp->ipAddressChoice.addressesOrRanges;
        for (; certrangep;
             certrangep = next_range(&certranges, certrangep), num6++)
        {
            ipAddrOrRangep =
                (struct IPAddressOrRangeA *)inject_casn(&ipAddrOrRangesp->self,
                                                        num6);
            make_IPAddrOrRange(ipAddrOrRangep,
                               certrangep->typ == IPv4 ? AF_INET : AF_INET6,
                               certrangep->lolim,
                               certrangep->hilim);
        }

    }
    // step 4
    if ((extp = find_extension(&paracertp->toBeSigned.extensions,
                               id_pe_autonomousSysNum, 0)))
    {
        int i;
        for (i =
             num_items(&extp->extnValue.autonomousSysNum.asnum.
                       asNumbersOrRanges.self); i > 0;
             eject_casn(&extp->extnValue.autonomousSysNum.asnum.
                        asNumbersOrRanges.self, --i));
    }
    if ((certrangep = &certranges.iprangep[num4 + num6])->typ == ASNUM)
    {
        if (!extp)
        {
            // at the end of extensions
            extp = (struct Extension *)inject_casn(&extsp->self,
                                                   num_items(&extsp->self));
        }
        // rewrite objid because step 1 cleared it
        write_objid(&extp->extnID, id_pe_autonomousSysNum);
        struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp =
            &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
        for (num4 = 0; certrangep;
             certrangep = next_range(&certranges, certrangep), num4++)
        {
            struct ASNumberOrRangeA *asNumOrRangep;
            asNumOrRangep =
                (struct ASNumberOrRangeA *)inject_casn(&asNumbersOrRangesp->
                                                       self, num4);
            make_ASnum(asNumOrRangep, certrangep);
        }
    }
}

/*
 * Function: Applies constraints to paracert
 * Inputs: number for enlarge (0) or perforate (>0)
 *         ptr to array of ranges
 *         number of ranges
 *         ptr to paracert
 * Returns: number of changes made
 * Procedure:
 * 1. Enlarge or perforate paracertificate's IPv4 addresses
 * 2. Enlarge or perforate paracertificate's IPv6 addresses
 * 3. Enlarge or perforate paracertificate's AS numbers
 *    Return count of changes made. if any
 */
static int modify_paracert(
    struct keyring *keyring,
    int run,
    struct Certificate *paracertp)
{
    int numcertrange = 0;
    int numrulerange = 0;
    int typ;
    int changes = 0;
    int did = 0;
    // start at beginning of SKI list and IPv4 family in certificate
    // beginning of SKI list
    struct iprange *rulerangep = ruleranges.iprangep;
    // step 1
    if (!(locflags & RESOURCE_NOUNION) || run)
    {
        typ = IPv4;
        if (rulerangep->typ == typ &&
            (did = run_through_typlist(run, numrulerange, numcertrange,
                                       &changes)) < 0)
            return did;
        while (rulerangep->typ == typ)
            rulerangep++;
        // step 2
        typ = IPv6;
        struct iprange *certrangep;
        for (certrangep = certranges.iprangep;
             certrangep->typ && certrangep->typ < typ; certrangep++);
        numcertrange = (certrangep - certranges.iprangep);
        numrulerange = (rulerangep - ruleranges.iprangep);
        if (rulerangep->typ == typ &&
            (did = run_through_typlist(run, numrulerange, numcertrange,
                                       &changes)) < 0)
            return did;
        while (rulerangep->typ == typ)
            rulerangep++;
        // step 3
        typ = ASNUM;
        for (certrangep = certranges.iprangep;
             certrangep->typ && certrangep->typ < typ; certrangep++);
        numcertrange = (certrangep - certranges.iprangep);
        numrulerange = (rulerangep - ruleranges.iprangep);
        if (rulerangep->typ == typ &&
            (did = run_through_typlist(run, numrulerange, numcertrange,
                                       &changes)) < 0)
            return did;
        remake_cert_ranges(paracertp);
    }
    did = sign_cert(keyring, paracertp);
    if (did < 0)
        return did;
    return changes;
}

/*
 * Function: Looks for any instances of ruleranges in the children of the
 *   cert and perforates them
 * Inputs: starting certificate
 * Procedure:
 * 1.  Get topcert's SKI
 *     FOR each of its children
 *       Get child's AKI
 *       IF haven't done this cert already, make a temporary done_cert
 *       ELSE use the one we have
 *       Make a paracert just in case
 * 2.    Punch out any listed resources
 * 3.    IF it's a temporary cert
 *         IF there was any error OR nothing was done, free the cert
 *         ELSE add the cert & paracert to the done list
 * 4.    IF something was done, call this function with this child
 */
static int search_downward(
    struct keyring *keyring,
    struct Certificate *topcertp)
{
    struct Extension *extp = find_extension(&topcertp->toBeSigned.extensions,
                                            id_subjectKeyIdentifier, 0);
    struct Certificate *childcertp;
    int ansr = 0;
    int numkid;
    int numkids;
    char pSKI[64];
    char cAKI[64];
    char cSKI[64];
    format_aKI(pSKI, &extp->extnValue.subjectKeyIdentifier);

    // Get list of children having pSKI as their AKI
    struct cert_answers *cert_answersp =
        find_cert_by_aKI((char *)0, pSKI, locscmp, locconp);
    numkids = cert_answersp->num_ansrs;
    if (numkids <= 0)
        /** @bug ignores error code without explanation */
        return 0;
    childcertp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
    Certificate(childcertp, (ushort)0);
    struct cert_answers mycert_answers;
    save_cert_answers(&mycert_answers, cert_answersp);
    // step 1
    for (numkid = 0; numkid < numkids; numkid++)
    {
        struct cert_ansr *cert_ansrp = &mycert_answers.cert_ansrp[numkid];
        if (get_casn_file(&childcertp->self, cert_ansrp->fullname, 0) < 0)
            /** @bug memory leak in mycert_answers.cert_ansrp */
            return ERR_SCM_COFILE;
        extp = find_extension(&childcertp->toBeSigned.extensions,
                              id_authKeyId, 0);
        memset(cAKI, 0, 64);
        format_aKI(cAKI, &extp->extnValue.authKeyId.keyIdentifier);
        extp = find_extension(&childcertp->toBeSigned.extensions,
                              id_subjectKeyIdentifier, 0);
        format_aKI(cSKI, &extp->extnValue.subjectKeyIdentifier);
        if (strcmp(cAKI, pSKI) || !strcmp(cSKI, cAKI))
            continue;
        struct done_cert *done_certp,
            done_cert;
        int have = 0;
        if (!(done_certp = have_already(cSKI)))
        {
            done_certp = &done_cert;
            fill_done_cert(done_certp, cSKI, cert_ansrp->filename, childcertp,
                           cert_ansrp->local_id, cert_ansrp->flags);
        }
        else
        {
            have = 1;
            if ((done_certp->perf & WASPERFORATEDTHISBLK))
                continue;
        }
        // step 2
        ansr = modify_paracert(keyring, 1, done_certp->paracertp);
        done_certp->perf |= (WASPERFORATED | WASPERFORATEDTHISBLK);
        if (have == 0)
        {
            // it is a temporary done_cert
            if (ansr <= 0)
            {
                delete_casn(&done_cert.origcertp->self);
                delete_casn(&done_cert.paracertp->self);
            }
            else
            {
                add_done_cert(&done_cert);
            }
        }
        if (ansr > 0)
            ansr = search_downward(keyring, done_certp->origcertp);
        if (ansr < 0)
            break;
    }
    free(mycert_answers.cert_ansrp);
    delete_casn(&childcertp->self);
    return ansr;
}

static int process_trust_anchors(
    struct keyring *keyring)
{
    struct cert_answers *cert_answersp = find_trust_anchors(locscmp, locconp);
    if (cert_answersp->num_ansrs < 0)
        /** @bug should return cert_answersp->num_ansrs */
        return ERR_SCM_UNSPECIFIED;
    int ansr = 0;
    int numkids = cert_answersp->num_ansrs;
    int numkid;
    struct Certificate *childcertp;
    childcertp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
    Certificate(childcertp, (ushort) 0);
    struct cert_answers mycert_answers;
    char cSKI[64];
    save_cert_answers(&mycert_answers, cert_answersp);
    struct Extension *extp;
    struct cert_ansr *cert_ansrp = &mycert_answers.cert_ansrp[0];
    // get them
    for (numkid = 0; numkid < numkids; numkid++, cert_ansrp++)
    {
        int i;
        struct done_cert *done_certp = &done_certs.done_certp[0];
        for (i = 0; i < done_certs.numcerts; i++, done_certp++)
        {
            // break if we have seen it
            if (done_certp->origID == cert_ansrp->local_id)
                break;
        }
        // then break if we found it
        if (i < done_certs.numcerts)
            break;
        // or if it is the LTA
        if (!strcmp(myrootfullname, cert_ansrp->fullname))
            continue;
        // or if it is an ETA
        if ((ansr = get_casn_file(&childcertp->self, cert_ansrp->fullname, 0))
            < 0)
            return ERR_SCM_COFILE;
        if (!(extp = find_extension(&childcertp->toBeSigned.extensions,
                                    id_pe_ipAddrBlock, 0)) &&
            !(extp = find_extension(&childcertp->toBeSigned.extensions,
                                    id_pe_autonomousSysNum, 0)))
            continue;
        if (i >= done_certs.numcerts)
        {
            struct done_cert done_cert;
            extp = find_extension(&childcertp->toBeSigned.extensions,
                                  id_subjectKeyIdentifier, 0);
            format_aKI(cSKI, &extp->extnValue.subjectKeyIdentifier);
            fill_done_cert(&done_cert, cSKI, cert_ansrp->filename, childcertp,
                           cert_ansrp->local_id, cert_ansrp->flags);
            /** @bug ignores error code without explanation */
            sign_cert(keyring, done_cert.paracertp);
            add_done_cert(&done_cert);
            /** @bug ignores error code without explanation */
            search_downward(keyring, done_cert.origcertp);
        }
    }
    return 0;
}

/*
 * Function: processes an SKI block, including ancestors
 * Inputs: ptr to base cert
 * Returns: 0 if OK else error code
 * Procedure:
 * 1. FOR each run until a self-signed certificate is done
 *      IF there's a conflict AND
 *        the conflict test returns error, return error code
 *      Modify paracert in accordance with run
 * 2.   IF current cert is self-signed, break out of FOR
 * 3.   Get the current cert's AKI
 *      Get that parent cert (and make paracert if necessaru)
 * 4. FOR all other self-signed certificates, search downward perforating
 *      them
 *    Return 0
 */
static int process_control_block(
    struct keyring *keyring,
    struct done_cert *done_certp)
{
    // step 1
    int run = 0;
    struct Extension *extp;
    struct done_cert *ndone_certp = (struct done_cert *)0;
    for (run = 0; 1; run++)
    {
        int ansr;
        if (((done_certp->perf & WASPERFORATED) && !run) ||
            ((done_certp->perf & WASEXPANDED) && run))
        {
            /**
             * @bug
             *     ignores error code without explanation?  (unclear
             *     without return value documentation for
             *     conflict_test())
             */
            if (conflict_test(run, done_certp))
            {
                // trim CR
                currskibuf[strlen(currskibuf) - 1] = 0;
                xsnprintf(errbuf, sizeof(errbuf), "in block %s at %s",
                          currskibuf, skibuf);
                *skibuf = 0;
                return ERR_SCM_USECONFLICT;
            }
        }
        // if resource_nounion, skip expanding
        if ((ansr = modify_paracert(keyring, run, done_certp->paracertp)) < 0)
            return ansr;
        done_certp->perf |= (!run) ? (WASEXPANDED | WASEXPANDEDTHISBLK) :
            (WASPERFORATED | WASPERFORATEDTHISBLK);
        // step 2
        if (!diff_casn(&done_certp->origcertp->toBeSigned.issuer.self,
                       &done_certp->origcertp->toBeSigned.subject.self))
            break;
        // step 3
        extp = find_extension(&done_certp->origcertp->toBeSigned.extensions,
                              id_authKeyId, 0);
        format_aKI(skibuf, &extp->extnValue.authKeyId.keyIdentifier);
        if ((ansr = get_CAcert(skibuf, &ndone_certp)) < 0)
            return ansr;
        done_certp = ndone_certp;
    }
    // oldcert is at a self-signed cert
    // for all ss certs
    /** @bug ignores error code without explanation */
    search_downward(keyring, done_certp->origcertp);
    return 0;
}

/*
 * Function processes successive "SKI blocks" until EOF
 * Inputs: File descriptor for SKI file
 *         buffer having first SKI line
 *         pointer to certificate??
 * Procedure:
 * 1. DO
 *      IF SKI entry not valid, return BADSKIBLOCK
 *      IF can't locate certificate having SKI with a valid chain to a
 *        trust anchor
 *        Return error
 *      Process the block
 *      Process the trust anchors with these constraints
 *    WHILE skibuf has anything
 */
static int process_control_blocks(
    struct keyring *keyring,
    FILE *SKI)
{
    struct done_cert *done_certp;
    int ansr;
    do
    {
        char *cc;
        char *skip;
        for (skip = &skibuf[4]; *skip == ' '; skip++);
        for (cc = skip; *cc == ':' || (*cc >= '0' && *cc <= '9') ||
             ((*cc | 0x20) >= 'a' && (*cc | 0x20) <= 'f'); cc++);
        if ((cc - skip) != 59 || *cc > ' ')
        {
            for (cc = skip; *cc != '\n'; cc++);
            if (*cc == '\n')
                *cc = 0;
            xsnprintf(errbuf, sizeof(errbuf), "Invalid SKI: %s", skip);
            return ERR_SCM_BADSKIBLOCK;
        }
        *cc = 0;
        if ((ansr = get_CAcert(skip, &done_certp)) < 0)
        {
            xsnprintf(errbuf, sizeof(errbuf), "No file for SKI %s.", skip);
            return ansr;
        }
        ruleranges.numranges = 0;
        ruleranges.iprangep = (struct iprange *)0;
        if ((ansr = getSKIBlock(SKI, skibuf, sizeof(skibuf))) < 0)
        {
            cc = strchr(skibuf, (int)'\n');
            if (cc && *cc)
                *cc = 0;
            if (*errbuf)
            {
                size_t errlen = strlen(errbuf);
                if (errlen + 1 < sizeof(errbuf))
                {
                    xsnprintf(&errbuf[errlen], sizeof(errbuf) - errlen, "at %s",
                              skibuf);
                }
            }
            else
                xsnprintf(errbuf, sizeof(errbuf), "Invalid prefix/range %s",
                          skibuf);
            // with error message in errbuf BADSKIBLOCK
            return ansr;
        }
        // otherwise skibuf has another SKI line or NULL

        if ((locflags & RESOURCE_NOUNION))
        {
            while (ruleranges.numranges)
                eject_range(&ruleranges, 0);
            int j;
            struct iprange *ciprangep;
            for (j = 0; j < certranges.numranges; j++)
            {
                struct iprange *riprangep = inject_range(&ruleranges, j);
                ciprangep = &certranges.iprangep[j];
                riprangep->typ = ciprangep->typ;
                memcpy(riprangep->lolim, ciprangep->lolim,
                       sizeof(ciprangep->lolim));
                memcpy(riprangep->hilim, ciprangep->hilim,
                       sizeof(ciprangep->hilim));
                if (ciprangep->text)
                {
                    riprangep->text = calloc(1, strlen(ciprangep->text) + 2);
                    strcpy(riprangep->text, ciprangep->text);
                }
            }
        }
        int err;

        err = process_control_block(keyring, done_certp);
        /** @bug ignores error code without explanation */
        process_trust_anchors(keyring);
        clear_ipranges(&ruleranges);
        if (err < 0)
            return err;
        int i;
        for (done_certp = &done_certs.done_certp[i = 0];
             i < done_certs.numcerts; done_certp++, i++)
        {
            done_certp->perf &= ~(WASPERFORATEDTHISBLK | WASEXPANDEDTHISBLK);
        }
        if (!*nextskibuf)
            break;
        strcpy(currskibuf, nextskibuf);
        strcpy(skibuf, nextskibuf);
    }
    while (1);
    return 0;
}

int read_SKI_blocks(
    scm *scmp,
    scmcon *conp,
    char *skiblockfile)
{
    /*
     * Procedure:
     * 1. Call parse_SKI_blocks
     * 2. Process all the control blocks
     *    IF no error,
     *      FOR each item in done_certs
     *        Flag the target cert in the database as having a para
     *        Sign the paracertificate
     *        Put it into database with para flag
     *    Free all and return error
     */
    Certificate(&myrootcert, (ushort) 0);
    int numcert;
    int locansr = 0;
    char locfilename[128];
    *locfilename = 0;
    int ansr = 0;
    struct keyring keyring = { NULL, NULL, NULL };
    // step 1
    FILE *SKI = fopen(skiblockfile, "r");
    LOG(LOG_DEBUG, "Starting LTA work");
    if (!SKI)
        ansr = ERR_SCM_NOSKIFILE;
    else if ((ansr = parse_SKI_blocks(&keyring, SKI, skiblockfile, skibuf,
                               sizeof(skibuf), &locflags)) >= 0)
    {
        if (!Xcp)
        {
            Xcp = (char *)calloc(1, 4);
            *Xcp = 'D';
        }
        strcpy(currskibuf, skibuf);
        locscmp = scmp;
        locconp = conp;
        if (findorcreatedir(locscmp, locconp, Xrpdir, &XrpdirId) < 0)
        {
            xsnprintf(errbuf, sizeof(errbuf), "Cannot find directory %s.",
                      Xrpdir);
            ansr = ERR_SCM_BADSKIFILE;
        }
        else
            ansr = process_control_blocks(&keyring, SKI);
    }
    struct done_cert *done_certp = done_certs.done_certp;
    for (numcert = 0; numcert < done_certs.numcerts; numcert++, done_certp++)
    {
        if (ansr >= 0)
        {
            // mark done_certp->cert as having para
            done_certp->origflags |= SCM_FLAG_HASPARACERT;
            if (done_certp->perf & WASEXPANDED)
                done_certp->origflags |= SCM_FLAG_ISTARGET;
            // put done_certp->paracert in database with para flag and
            // flag original cert as having a paracert
            if (locansr >= 0 && (locansr = add_paracert2DB(done_certp)) < 0)
            {
                LOG(LOG_DEBUG, "Error adding paracert %s to DB",
                        done_certp->filename);
                strcpy(locfilename, done_certp->filename);
                *skibuf = 0;
            }
        }
        delete_casn(&done_certp->origcertp->self);
        delete_casn(&done_certp->paracertp->self);
        free(done_certp->origcertp);
        free(done_certp->paracertp);
    }
    if (!ansr)
        *skibuf = 0;
    if (!ansr)
        ansr = locansr;
    if (SKI)
        fclose(SKI);
    delete_casn(&myrootcert.self);
    if (Xcp)
    {
        free(Xcp);
        Xcp = NULL;
    }
    if (Xaia)
    {
        free(Xaia);
        Xaia = NULL;
    }
    free(Xcrldp);
    Xcrldp = NULL;
    free_keyring(&keyring);
    if (*errbuf)
    {
        if (strlen(errbuf) + strlen(".") + 1 <= sizeof(errbuf) &&
            errbuf[strlen(errbuf) - 1] != '.' &&
            errbuf[strlen(errbuf) - 1] != '\n')
            strcat(errbuf, ".");
        LOG(LOG_ERR, "%s", errbuf);
    }
    LOG(LOG_DEBUG, "Finished LTA work");
    return ansr;
}
