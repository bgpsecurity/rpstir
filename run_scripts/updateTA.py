#!/usr/bin/python

import os, sys, filecmp, shutil, subprocess, tempfile
from optparse import OptionParser
from base64 import b64encode

def updateTA_main():
    overallret = 0
    for f in args:
        ret = update_one_TA(f)
        if ret != 0:
            overallret = ret
    return overallret

def update_one_TA(tal_file):
    print "Processing trust anchor locator: " + tal_file
    [rsync_uri, pubkey_b64] = parse_TAL_file(tal_file)
    if options.verbose:
        print "URI: " + rsync_uri
        print "PublicKeyInfo: " + pubkey_b64

    # Compute local path to TA
    local_path = compute_local_path(rsync_uri, ta_repo_path)
    
    # Copy existing TA (if any) to backup file
    is_existing_TA = False
    local_backup_path = None
    if os.path.isfile(local_path):
        is_existing_TA = True
        local_backup_path = local_path + ".bak"
        shutil.copy2(local_path, local_backup_path)
        if options.verbose:
            print "Backed up existing certificate: %s" % local_path

    # Download new/updated TA using rsync
    ret = rsync_download(rsync_uri, local_path)
    if ret != 0:
        print >>sys.stderr,\
            "Warning: could not download %s to %s." % (rsync_uri, local_path)
        if is_existing_TA:
            print >>sys.stderr,\
                "If you wish to remove this trust anchor, run 'rcli -d %s'" % \
                (local_path)
        return ret

    # Did the TA change?
    TA_has_changed = False
    if not is_existing_TA or \
            not filecmp.cmp(local_path, local_backup_path, shallow=False):
        TA_has_changed = True

    # Finish if done
    if not TA_has_changed:
        print "Trust anchor has not changed (%s)" % rsync_uri
        return 0

    # Is the new TA signed correctly?
    ret = verify_TA_signature(local_path)
    if ret != 0:
        print >>sys.stderr, "Signature verification failed for %s" % local_path
        if is_existing_TA:
            print >>sys.stderr,\
                "Restoring old certificate from backup: %s --> %s"\
                % (local_backup_path, local_path)
            shutil.move(local_backup_path, local_path)
        return ret

    # Does the new TA have the right public key info?
    ret = verify_SubjectPubKeyInfo(local_path, pubkey_b64)
    if ret != 0:
        print >>sys.stderr, "Public key is wrong for %s" % local_path
        if is_existing_TA:
            print >>sys.stderr,\
                "Restoring old certificate from backup: %s --> %s"\
                % (local_backup_path, local_path)
            shutil.move(local_backup_path, local_path)
        return ret

    # If necessary, remove existing TA from database.
    existing_TA_removed = False
    if is_existing_TA and TA_has_changed:
        if options.verbose:
            print "Removing existing TA from db: " + local_path
        ret = remove_from_db(local_path)
        if ret != 0:
            print >>sys.stderr, \
                "Could not remove existing TA from db: %s.  Aborting" \
                % (local_path)
            print >>sys.stderr,\
                "Restoring old certificate from backup: %s --> %s"\
                % (local_backup_path, local_path)
            shutil.move(local_backup_path, local_path)
            return ret
        existing_TA_removed = True

    # Add new TA to database.
    ret = subprocess.call([rcli_path, '-y', '-F', local_path])
    
    # If failure, restore old TA in the filesystem and database.
    if ret != 0:
        print >>sys.stderr, \
            "Error adding TA into database (%s)" % local_path
        if is_existing_TA:
            print >>sys.stderr,\
                "Restoring old certificate from backup: %s --> %s"\
                % (local_backup_path, local_path)
            shutil.move(local_backup_path, local_path)
        if existing_TA_removed:
            restore_ret = subprocess.call([rcli_path, '-y', '-F', local_path])
            if restore_ret != 0:
                print >>sys.stderr, \
                    "Error: could not restore old TA, this is bad!"

    print "Trust anchor updated (%s) " % rsync_uri
    return ret

def parse_TAL_file(tal_file):
    """Return [rsyncURI, subjectPublicKeyInfo] as a pair of strings."""
    f = open(tal_file, "r")

    # First non-blank line is the TA rsync URI
    rsync_uri = None
    while not rsync_uri:
        rsync_uri = f.readline().strip()

    # Base64-encoded SubjectPublicKeyInfo is the rest of the file,
    # with all whitespace removed.
    words = []
    for line in f:
        for w in line.strip().split():
            words.append(w)
    pubkey_b64 = "".join(words)
    return [rsync_uri, pubkey_b64]

def compute_local_path(rsync_uri, local_repo_path):
    if rsync_uri.startswith("rsync://"):
        relative_path = rsync_uri.replace("rsync://","")
    else:
        relative_path = rsync_uri
    return local_repo_path.rstrip("/") + "/" + relative_path

def rsync_download(uri, targetpath):
    if options.verbose:
        print "Downloading %s --> %s" % (uri, targetpath)

    # Make sure target directory exists
    target_dir = os.path.dirname(targetpath)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        
    # WARNING: we do not check uri or targetpath for malicious input!
    return subprocess.call([options.rsync_cmd, uri, targetpath])

def verify_TA_signature(cert_path):
    if options.verbose:
        print "Verifying signature on " + cert_path

    # Create temporary PEM-encoded certificate file
    f = open(cert_path, "rb")
    pem_f = tempfile.NamedTemporaryFile(delete=False)
    pemfilename = pem_f.name
    ret = subprocess.call([options.openssl_cmd, 'x509', '-inform', 'DER'],
                          stdin=f, stdout=pem_f)
    f.close()
    pem_f.close()
    if ret != 0:
        os.remove(pemfilename)
        print >>sys.stderr, "Error: failed to make PEM version of " + cert_path
        return ret
    if options.verbose:
        print "Created temporary PEM version at: " + pemfilename
    
    # Invoke OpenSSL's verify
    p1 = subprocess.Popen([options.openssl_cmd, 'verify',
                           '-check_ss_sig', pemfilename],
                          stdout=subprocess.PIPE)
    lines = p1.communicate()[0].splitlines()
    if lines[-1].strip() == "OK":
        if options.verbose:
            print "Signature verified successfully"
        ret = 0
    else:
        ret = -1
    
    # Clean up
    os.remove(pemfilename)
    
    return ret

def verify_SubjectPubKeyInfo(cert_path, pubkey_base64):
    p1 = subprocess.Popen([rpki_root + "/cg/tools/extractPubKeyInfo",
                           cert_path], stdout=subprocess.PIPE)
    pubkey_binary = p1.communicate()[0]
    ret = p1.returncode
    if ret != 0:
        print >>sys.stderr, "Error extracting Subject Public Key Info from %s"\
            % cert_path
        return ret
    if b64encode(pubkey_binary) != pubkey_base64:
        return -1
    if options.verbose:
        print "SubjectPublicKeyInfo verified successfully"
    return 0

def remove_from_db(cert_path):
    return subprocess.call([rcli_path, '-d', cert_path])

###############################################################################

if __name__ == "__main__":
    
    # Parse command line arguments
    usage = "usage: %prog [options] file.tal [file2.tal ...]"
    parser = OptionParser(usage=usage)
    parser.add_option("-r", "--rsync", dest="rsync_cmd", default="rsync",
                      help="PATH to rsync executable", metavar="PATH")
    parser.add_option("-s", "--ssl", dest="openssl_cmd", default="openssl",
                      help="PATH to openssl executable", metavar="PATH")
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="print gory details to stdout")
    (options, args) = parser.parse_args()
    if len(args) == 0:
        parser.print_help()
        sys.exit(1)
    
    # Get top-level RPKI directory, and compute local repository cache
    # path based on $RPKI_ROOT environment variable.
    rpki_root = os.environ["RPKI_ROOT"].strip().rstrip("/")
    repo_path = rpki_root + "/REPOSITORY"
    ta_repo_path = repo_path + "/trustanchors"
    rcli_path = rpki_root + "/proto/rcli"
    print "Using RPKI root directory: " + rpki_root
    print "Using local repository path: " + repo_path
    print "Using local trust anchor path: " + ta_repo_path
    
    sys.exit(updateTA_main())
