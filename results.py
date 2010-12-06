#!/usr/bin/python

from subprocess import Popen, PIPE
import os
from optparse import OptionParser


#
# Parse command line options
#

parser = OptionParser()
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print gory details to stdout")
(options, args) = parser.parse_args()

#
# Get top-level RPKI directory, and compute local repository cache
# path based on $RPKI_ROOT environment variable.
#

rpki_root = os.environ["RPKI_ROOT"].strip().rstrip("/")
repo_path = rpki_root + "/REPOSITORY"
print "Using RPKI root directory: " + rpki_root
print "Using local repository path: " + repo_path

#
# Define some useful functions which invoke command line tools.
#

def find_files_with_extension(absolute_path, ext):
    p1 = Popen(["find", absolute_path, "-name", "*." + ext], stdout=PIPE)
    return p1.communicate()[0].splitlines()

def find_validated_objects_in_db(object_type):
    p1 = Popen([rpki_root + "/proto/query", "-t", object_type,
                "-d", "pathname"], stdout=PIPE)
    return [line.split()[2] for line in p1.communicate()[0].splitlines()]

def find_all_objects_in_db(object_type):
    p1 = Popen([rpki_root + "/proto/query", "-t", object_type,
                "-d", "pathname", "-i"], stdout=PIPE)
    return [line.split()[2] for line in p1.communicate()[0].splitlines()]


#
# Results for certificates
#

print
print "-" * 79
print "Certficate Information:"
print "-" * 79

# In filesystem
all_cert_files = find_files_with_extension(repo_path, "cer")
ca_cert_files = []
ee_cert_files = []
for f in all_cert_files:
    if f.find("EEcertificates") != -1:
        ee_cert_files.append(f)
    else:
        ca_cert_files.append(f)
print "CA cert files: %d" % len(ca_cert_files)
print "EE cert files: %d" % len(ee_cert_files)
print "Total cert files: %d" % len(all_cert_files)

# In database
db_validated_certs = find_validated_objects_in_db("cert")
db_all_certs = find_all_objects_in_db("cert")
db_unknown_certs = list(set(db_all_certs) - set(db_validated_certs))
invalid_certs = list(set(all_cert_files) - set(db_all_certs))
print "Validated certs: %d" % len(db_validated_certs)
print "Status-unknown certs: %d" % len(db_unknown_certs)
print "Invalid or duplicate certs: %d" % len(invalid_certs)

if options.verbose:
    db_unknown_certs.sort()
    invalid_certs.sort()
    if db_unknown_certs:
        print "\nStatus-unknown certs:\n", "\n".join(db_unknown_certs)
    if invalid_certs:
        print "\nInvalid or duplicate certs:\n", "\n".join(invalid_certs)


#
# Results for CRLs
#

print
print "-" * 79
print "CRL Information:"
print "-" * 79

# In filesystem
all_crl_files = find_files_with_extension(repo_path, "crl")
print "Total crl files: %d" % len(all_crl_files)

# In database
db_validated_crls = find_validated_objects_in_db("crl")
db_all_crls = find_all_objects_in_db("crl")
db_unknown_crls = list(set(db_all_crls) - set(db_validated_crls))
invalid_crls = list(set(all_crl_files) - set(db_all_crls))
print "Validated crls: %d" % len(db_validated_crls)
print "Status-unknown crls: %d" % len(db_unknown_crls)
print "Invalid or duplicate crls: %d" % len(invalid_crls)

if options.verbose:
    db_unknown_crls.sort()
    invalid_crls.sort()
    if db_unknown_crls:
        print "\nStatus-unknown crls:\n", "\n".join(db_unknown_crls)
    if invalid_crls:
        print "\nInvalid or duplicate crls:\n", "\n".join(invalid_crls)


#
# Results for ROAs
#

print
print "-" * 79
print "ROA Information:"
print "-" * 79

# In filesystem
all_roa_files = find_files_with_extension(repo_path, "roa")
print "Total roa files: %d" % len(all_roa_files)

# In database
db_validated_roas = find_validated_objects_in_db("roa")
db_all_roas = find_all_objects_in_db("roa")
db_unknown_roas = list(set(db_all_roas) - set(db_validated_roas))
invalid_roas = list(set(all_roa_files) - set(db_all_roas))
print "Validated roas: %d" % len(db_validated_roas)
print "Status-unknown roas: %d" % len(db_unknown_roas)
print "Invalid or duplicate roas: %d" % len(invalid_roas)

if options.verbose:
    db_unknown_roas.sort()
    invalid_roas.sort()
    if db_unknown_roas:
        print "\nStatus-unknown roas:\n", "\n".join(db_unknown_roas)
    if invalid_roas:
        print "\nInvalid or duplicate roas:\n", "\n".join(invalid_roas)


#
# Results for Manifests
#

print
print "-" * 79
print "Manifest Information:"
print "-" * 79

# In filesystem
all_mft_files = []
all_mft_files.extend(find_files_with_extension(repo_path,
                                               "mft"))
all_mft_files.extend(find_files_with_extension(repo_path,
                                               "mnf")) # FIXME: remove later
print "Total manifest files: %d" % len(all_mft_files)

# In database
db_validated_mfts = find_validated_objects_in_db("man")
db_all_mfts = find_all_objects_in_db("man")
db_unknown_mfts = list(set(db_all_mfts) - set(db_validated_mfts))
invalid_mfts = list(set(all_mft_files) - set(db_all_mfts))
print "Validated manifests: %d" % len(db_validated_mfts)
print "Status-unknown manifests: %d" % len(db_unknown_mfts)
print "Invalid or duplicate manifests: %d" % len(invalid_mfts)

if options.verbose:
    db_unknown_mfts.sort()
    invalid_mfts.sort()
    if db_unknown_mfts:
        print "\nStatus-unknown manifests:\n", "\n".join(db_unknown_mfts)
    if invalid_mfts:
        print "\nInvalid or duplicate manifests:\n", "\n".join(invalid_mfts)

# Informational message
if not options.verbose:
    print "\nHint: to see lists of unknown/invalid objects, run with -v."
