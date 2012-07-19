#include "rpki-object/certificate.h"


struct Extension *find_extension(
    struct Extensions *extsp,
    const char *oid,
    bool create)
{
    struct Extension *extp;
    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oid);
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp && create)
    {
        int num = num_items(&extsp->self);
        extp = (struct Extension *)inject_casn(&extsp->self, num);
        if (extp)
            write_objid(&extp->extnID, oid);
    }
    return extp;
}

struct Extension *make_extension(
    struct Extensions *extsp,
    const char *oid)
{
    struct Extension *extp = find_extension(extsp, oid, false);
    if (extp == NULL)
    {
        extp = (struct Extension *)inject_casn(&extsp->self,
                                               num_items(&extsp->self));
        if (extp == NULL)
        {
            return NULL;
        }
    }
    else
    {
        clear_casn(&extp->self);
    }

    write_objid(&extp->extnID, oid);

    return extp;
}
