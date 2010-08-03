#!/usr/bin/env python

# Run test cases using test driver file test.conf
# open test driver file
#  -- run through every line in the file and perform the specified function
#     For BBN this means using the rcli and query programs to insert/delete
#     certificates from the database or query the database for the cert
#     cases:
#      PATH - set the certificate path (for all certificates that aren't
#             specified by full pathname)
#      ECHO - print string to stdout
#      ADD - add this certificate into the repository (and verify it was added)
#      DELETE - delete this certificate from the repository
#      DISPLAY - query the database for this repository

import os
import sys
import traceback
import subprocess
from optparse import OptionParser

global certpath
global verbose

def err(code, errstring):
    print errstring    
    sys.exit(code)


def run_tests(cfgfile):
    """ run all test cases"""

    # open test config file
    try:
        if not os.path.exists(cfgfile):
            err(1,("Test configuration file does not exist: %s") % (cfgfile))

        file = open(cfgfile)
        for line in file:
            if not line.startswith("#") and len(line) > 1:
                process_input(line)


    except IOError:
#        traceback.print_exc()
        err(1,("File %s does not exist") % (cfgfile))
        

    return

def process_input(line):
    """
    Process line from input configuration file.
    split the command into fields separated by space
    The first field is the command. Subsequent fields are
    based upon the command.
    """
    global certpath
    line = line.strip()
    fields = line.split()

    # convert command to upper case to compare
    command = fields[0].upper().strip()
    # switch based upon command

    # add the certificate to the repository
    # first field is cert name, second field is either
    # trusted (don't validate) or expected result (true or false)
    # defaults to not trusted and don't display results
    if command == 'ADD':
        trusted = False
        display = False
        cert = fields[1].strip()
        if len(fields) > 2:
            arg2 = fields[2].upper()
            if arg2.startswith('TRUSTED'):
                trusted = True
            elif arg2 == 'TRUE':
                display = True
                expected = True
            elif arg2 == 'FALSE':
                display = True
                expected = False

        # attempt to add the certificate to the repository
        # Note: if the file does not exist we don't attempt to 
        # add it so no need to query the repository to see if it was added
        if add_to_repository(cert, trusted) and display:
            display_cert(cert,expected)

    # delete certificate from the repository
    elif command == 'DELETE':
        cert = fields[1]
        del_from_repository(cert)

    # echo the line directly from config file 
    elif command == 'ECHO':
        text = line.strip(command)
        if len(text) > 0:
            print text
        else:
            print

    
    # display cert in database and print pass or fail
    # based upon expected results (from command line)
    elif command == 'DISPLAY':
        result = False
        cert = fields[1]
        if fields[2].upper() == 'TRUE':
            result = True
        display_cert(cert,result)

    elif command == 'PATH':
        try:
            p = fields[1]
            if os.path.exists(p):
                certpath = p
            else:
                err(2,'Path %s does not exist') % (p)
        except IOError:
#            traceback.print_exc()
            err(1,("Path %s does not exist") % (cfgfile))
            
    else:
        return

    return

def display_cert(cert, result):
    """
    Query the repository to see if the certificate is there - compare
    parse query results looking for cert - 
     if there and expected result true then print PASS with flags
     if there and expected result false then print FAIL
     if not there and expected result true then print FAIL
     if not there and expected result false then print PASS

    BBN software case:
       query -t cert -d filename -d flags
    """

    if cert is None:
        return

    command = ('query -t cert -d filename -d flags')
    out, err = exec_command(command)
    if out is not None:
        if cert in out:
            if result:
                print ("%s: PASS") % (cert)
            else:
                print ("%s: FAIL") % (cert)
        else:
            if result:
                print ("%s: FAIL") % (cert)
            else:
                print ("%s: PASS") % (cert)

    if err is not None:
        print err
    return    


def add_to_repository(cert, trusted):
    """
    Add certificate to repository
    BBN softrware case:
      run rcli command to add certificate to database (rcli -y -f cert)

    Returns False if we did not attempt to add certificate
            True if we did try to add certificate (note it may have failed
                 to be added)
    """
    global verbose
    
    if cert is None:
        return

    fullpath_cert = create_fullpath_cert(cert)
    if not os.path.exists(fullpath_cert):
        print ('File Not Found: %s\n') % (fullpath_cert)
        return (False)
    else:
        if trusted:
            command = ("rcli -y -F %s") % (fullpath_cert)
        else:
            command = ("rcli -y -f %s") % (fullpath_cert)
        out, err = exec_command(command)
        if verbose and err:
            print err
            
    return True

def del_from_repository(cert):
    """ 
    Delete certificate from the database
    BBN software case:
       run rcli command to delete certificate from the database
       rcli -y -d <cert>
    """

    if cert is None:
        return

    fullpath_cert = create_fullpath_cert(cert)
    command = ("rcli -y -d %s") % (fullpath_cert)
    out,err = exec_command(command)

    return

def create_fullpath_cert(cert):
    """create a full pathname for the cert if it isn't already one
    """
    global certpath

    # if it starts with a full / then it must already be a fullpath name
    if cert.startswith('/'):
        return cert

    if certpath is None:
        return cert

    # join pathname with certificate name, add slash if necessary
    if certpath.endswith("/"):
        fullpath_cert = ("%s%s") % (certpath, cert)
    else:
        fullpath_cert = ("%s/%s") % (certpath, cert)

    return fullpath_cert


def exec_command(cmd):
    """ execute the specified command
    """

    p = subprocess.Popen(cmd, shell=True, stdout = subprocess.PIPE,
                         stderr = subprocess.PIPE)
    out,err = p.communicate()
    return( out, err )


def main(argv=None):
    
    usage = """usage: %prog [options] <test.conf> 
    Run all test cases specified in the test configuration file 
    """

    global verbose
    global certpath

    # default certificate path to current directory
    certpath = '.'      

    if argv is None:
        argv = sys.argv

    parser = OptionParser(usage)
    parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print error or output messages from executed commands")

    opts,args = parser.parse_args()
    verbose = opts.verbose

    try:
        if len(argv) < 2:
            parser.error('Missing Test Configuration File')
            parser.print_help()
            sys.exit(-1)
            
        config_file = args[0]
        run_tests(config_file)

    except (KeyboardInterrupt, SystemExit):
        sys.exit()

if __name__ == "__main__":
    sys.exit(main())
