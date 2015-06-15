#include <stdio.h>
#include "rpki/cms/roa_utils.h"
#include "util/cryptlib_compat.h"
#include "util/gettext_include.h"

/*
 * $Id$ 
 */


int main(
    int argc,
    char **argv)
{

	//Set gettext up
	setlocale(LC_MESSAGES, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

    struct CMS cms;
    struct Certificate *certp;

    CMS(&cms, 0);
    if (argc < 2)
        fprintf(stderr, _("Need argvs for CMS(s)\n"));
    else
        for (argv++; argv && *argv; argv++)
        {
            if (get_casn_file(&cms.self, argv[0], 0) < 0)
                fprintf(stderr, _("Reading CMS failed\n"));
            else if (!
                     (certp =
                      (struct Certificate *)member_casn(&cms.content.
                                                        signedData.
                                                        certificates.self, 0)))
                fprintf(stderr, _("Couldn't get certificate in CMS\n"));
            else
            {
                char *n = _("something else");
                if (!diff_objid
                    (&cms.content.signedData.encapContentInfo.eContentType,
                     id_roa_pki_manifest))
                    n = argv[0];
                else if (!diff_objid
                         (&cms.content.signedData.encapContentInfo.
                          eContentType, id_routeOriginAttestation))
                    n = "ROA";
                fprintf(stderr, _("Checking %s %s\n"), n,
                        (check_sig(&cms, certp) <
                         0) ? _("failed." : "SUCCEEDED!"));
            }
        }
    return 0;
}
