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
    struct CMS roa;
    int siz;

    CMS(&roa, 0);
    if (argc < 2)
        fprintf(stderr, _("Need argv[1] for roa\n"));
    else
    {
        printf(_("Testing %s and %s\n"), argv[1], argv[2]);
        if ((siz = get_casn_file(&roa.self, argv[1], 0)) < 0)
            fprintf(stderr, _("Reading roa failed at %d (%X) %s\n"), -siz, -siz,
                    casn_err_struct.asn_map_string);
        else
        {
            fprintf(stderr, _("Checking %s\n"),
                    (roaValidate2(&roa) < 0) ? _("failed." : "SUCCEEDED!"));
        }
    }
    return 0;
}
