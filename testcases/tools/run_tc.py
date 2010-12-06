#!/usr/bin/env python

# Run test cases using test driver file test.conf
# open test driver file
#  -- run through every line in the file and perform the specified function
#     For BBN this means using the rcli and query programs to insert/delete
#     certificates from the repository or query the repository for the cert.
#     Test driver file language:
#      PATH - set the certificate path (for all certificates that aren't
#             specified by full pathname)
#      ECHO - print string to stdout
#      ADD - add this certificate into the repository (and
#            optionally verify that it was added)
#      DELETE - delete this certificate from the repository
#      DISPLAY - query the repository the certificate and report pass or fail
#                based upon the query results and the expected result (Note
#                the expected result is passed on the DISPLAY line
#
# See Notes in sample test.conf file for more information on how to define
# a test case.

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
    """ Open driver file and run all test cases specified
    by the file.
    """

    # open test config file
    try:
        if not os.path.exists(cfgfile):
            err(1,("Test configuration file does not exist: %s") % (cfgfile))

        try:
            file = open(cfgfile)
            for line in file:
                line = line.strip()
                if not line.startswith("#") and len(line) > 1:
                    process_input(line)
        except IOError, e:
            err(2,('Error Opening file %s, %s' % (cfgfile, str(e))))


    except IOError:
        err(1,("File %s does not exist") % (cfgfile))
         

    return

def process_input(line):
    """
    Process a line from the input configuration file.
    split the line into fields separated by space
    The first field is the command. Subsequent fields are
    based upon the command.
    """
    global certpath

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
        # Note: if the file does not exist (add_to_repository returns
        # false) we don't query the repository to see if it was added
        fullpath_cert = create_fullpath_cert(cert)
        if fullpath_cert is not None:
            if add_to_repository(fullpath_cert, trusted) and display:
                display_cert(cert,expected)

    # delete certificate (not fullpath name) from the repository
    elif command == 'DELETE':
        cert = fields[1]
        fullpath_cert = create_fullpath_cert(cert)
        if fullpath_cert is not None:
            del_from_repository(fullpath_cert)

    # echo the line directly from config file 
    elif command == 'ECHO':
        text = line.strip(command)
        if len(text) > 0:
            print text
        else:
            return

    # query the repository to see if the cert is there, print pass or fail
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
                err(2,('Path %s does not exist' % (p)))
        except IOError:
#            traceback.print_exc()
            err(1,("Path %s does not exist") % (cfgfile))
            
    else:
        print ('Invalid command: ignoring line %s' % line)
        return

    return

def display_cert(cert, result):
    """
    Query the repository to see if the certificate is there
    parse query results looking for cert - 
     if there and expected result true then print PASS
     if there and expected result false then print FAIL
     if not there and expected result true then print FAIL
     if not there and expected result false then print PASS

    BBN software case:
       query -t cert -d filename -d flags
    """

    if cert is None:
        return

    # get the base filename of the cert
    cert_fname = os.path.basename(cert)
    if len(cert_fname) <= 0:
        print ('Filename error with cert %s' % cert)
        return

    command = ('query -t cert -d filename -d flags')
    out, err = exec_command(command)
    if out is not None:
#        print 'QUERY OUTPUT: %s' % out
        if cert_fname in out:
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

    Returns False if we did not attempt to add certificate (invalid file name)
            True if we did try to add certificate (note it may have failed
                 to be added but that is what we are testing)
    """
    global verbose
    
    if cert is None:
        return

    if not os.path.exists(cert):
        print ('File Not Found: %s\n') % (cert)
        return (False)
    else:
        if trusted:
            command = ("rcli -y -F %s") % (cert)
        else:
            command = ("rcli -y -f %s") % (cert)
        out, err = exec_command(command)
        print out
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

    command = ("rcli -y -d %s") % (cert)
    out,err = exec_command(command)

    return

def create_fullpath_cert(cert):
    """create a full pathname for the cert if it isn't already one
    """
    global certpath

    # check to see if it is already a full pathname
    # or a relative pathname
    if cert.startswith('/') or cert.startswith('../'):
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
    Run all test cases specified by the test configuration file 
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
                  help="don't print error or output messages from executed repository commands")

    opts,args = parser.parse_args()
    verbose = opts.verbose

    try:
        if len(argv) < 2:
            print ('ERROR: Missing Test Configuration File\n')
            parser.print_help()
            sys.exit(-1)
            
        config_file = args[0]
        run_tests(config_file)

    except (KeyboardInterrupt, SystemExit):
        sys.exit()

if __name__ == "__main__":
    sys.exit(main())
