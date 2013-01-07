#include "keyfile.h"


bool fillPublicKey(
    struct casn *spkp,
    const char *keyfile)
{
    struct Keyfile kfile;
    Keyfile(&kfile, (ushort) 0);
    if (get_casn_file(&kfile.self, keyfile, 0) < 0)
        return false;
    int val = copy_casn(spkp, &kfile.content.bbb.ggg.iii.nnn.ooo.ppp.key);
    if (val <= 0)
        return false;
    return true;
}
