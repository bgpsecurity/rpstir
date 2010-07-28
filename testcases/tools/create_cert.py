#!/usr/bin/env python

import os
import sys
import glob
import subprocess

from optparse import OptionParser

def make_cert(fullname, root):
    """ make the cert"""

    cert = root + '.cer'
    cmdline = (('rr < %s > %s') %
               (fullname, cert))
    print cmdline
    p = subprocess.Popen(cmdline, shell=True, stdout = subprocess.PIPE,
                         stderr = subprocess.PIPE)
    print p.communicate()[1]
    os.chmod(cert,0666)
    return cert

def sign_cert(cert):
    """ sign the cert using a key from the same directory as the
    certificate. The key is based upon the name of the certificate"""

    key = None
    dir = None
    
    if cert is None:
        return

    dir = os.path.dirname(cert)
    if dir is not None and dir is not '':
        has_slash = dir.endswith('/')
        if not has_slash:
            dir = dir + '/'

    certname = os.path.basename(cert)

    if certname.startswith('C'):
        key = dir + 'P.p15'
    elif certname.startswith('P'):
        key = dir + 'R.p15'
    elif certname.startswith('R'):
        key = dir + 'R.p15'
    elif certname.startswith('GC'):
        key = dir + 'C.p15'
    elif certname.startswith('GGC'):
        key = dir + 'GC.p15'

    if key is None:
        print ('Error: cannot sign certificate %s, no key' % (cert))
        return

    cmdline = ('sign_cert %s %s update') % (cert, key)
    print cmdline
    p = subprocess.Popen(cmdline, shell=True, stdout = subprocess.PIPE,
                         stderr = subprocess.STDOUT)
    print p.communicate()[0]
    return 

def main(argv=None):
    
    usage = """usage: %prog [options] <filename.raw> 
    Create a signed certificate from a raw asn file.

    Note: filename must be a name.raw file or \"*.raw\" (with quotes)

    rr is run on the .raw file(s) and output is stored in a \".cer\" file  
    The \".cer\" file is then signed using sign_cert. 

    The key used to sign the cert is determined by  
    the first letter of the filename, i.e.: 
      PXXX.cer is signed by R.p15 
      CXXX.cer is signed by P.p15 
      GCXXX.cer is signed by C.p15 
      GGCXXX.cer is signed by GC.p15"""

    if argv is None:
        argv = sys.argv

    parser = OptionParser(usage)
    opts,args = parser.parse_args()

    if len(argv) < 2:
        parser.error('\nMissing Input Argument')
        parser.print_usage()
        sys.exit(-1)

    dirlist = glob.glob(argv[1])
    
    for dir in dirlist:
        root, ext = os.path.splitext(dir)
        if ext == '.raw':
            cert = make_cert(dir, root)    
            sign_cert(cert)
        else:
            print 'not processing ' + dir
            

if __name__ == "__main__":
    sys.exit(main())
