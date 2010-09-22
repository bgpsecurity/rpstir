#/* ***** BEGIN LICENSE BLOCK *****
# *
# * BBN Address and AS Number PKI Database/repository software
# * Version 3.0-beta
# *
# * US government users are permitted unrestricted rights as
# * defined in the FAR.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT
# * WARRANTY OF ANY KIND, either express or implied.
# *
# * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# *
# * Contributor(s):  Brenton Kohler(bkohler@bbn.com)
# *
# * ***** END LICENSE BLOCK ***** */

from threading import Thread
from subprocess import Popen
import getopt, sys, os, Queue, time, socket, subprocess, logging, commands

BLOCK_TIMEOUT = 1
IP_LISTENER = '127.0.0.1'

#
# A short utility function to handle tcp sending and error checking
#
def send_to_listener(data,logger):
    #This needs a lot of error checking
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
        s.connect((IP_LISTENER, portno))
        bytesSent = s.send(data)
        while bytesSent < len(data):
            bytesSent = s.send(data)
        s.close()
    except:
        logger.error("A socket error occurred")

#
# This class handles the RSYNC threads
#
class RSYNC_thread(Thread):
    def run(self):
        try:
            # The python queue is synchronized so this is safe
            nextURI = URIPool.get(True, BLOCK_TIMEOUT)
        except Queue.Empty:
            print "queue empty. %s " % self.getName()
            return
        cli = logging.getLogger('Thread: %s: ' % self.getName())
        while not nextURI=="" : #while a URI has been popped
            stderror = ""
            logFileName = (logDir + "/rsync_thread_%s.log") % (self.getName())
            rsync_log = ("%s/%s.%f" % (logDir,nextURI,time.time()))

            #build and run the rsync command. This may block for awhile but that
            #is the beauty of the multiple threads.
            rsyncCom = "%s -airz --del --timeout=10 rsync://%s/ %s/%s 1> %s" \
                       % (rsyncDir, nextURI, repoDir, nextURI, rsync_log)

            p = Popen(rsyncCom, shell=True, stderr=subprocess.PIPE)
            stderror = p.communicate()[1]
            rcode = p.returncode

            cli.info( (nextURI + " had return code %s") % (rcode) )
            if not stderror == "":
                cli.error( 'rsync returned errors: %s' % stderror )
            cli.info( rsyncCom )
            
            if rcode == 30:
                # this is an error code for timeout, sleep then re-run
                time.sleep(5)
                #re-run the rsync command
                rcode = subprocess.call(rsyncCom, shell=True)
                cli.info( (nextURI + " 2nd attempt: %s") % (rcode))
 
            elif rcode == 35:
                # this is an error code for timeout, sleep then re-run
                time.sleep(5)
                #re-run the rsync command
                rcode = subprocess.call(rsyncCom, shell=True)
                cli.info( (nextURI + " 2nd attempt: %s") % (rcode))

            if rcode == 0:
                #if the rsync ran successful, notify Listener
                cli.info( 'Notifying the listener' ) 
                data = ("%s %s/%s %s") % \
                              (nextURI, repoDir, nextURI, rsync_log)
                              
                send_to_listener(data,cli)

            #get next URI
            try:
                # The python queue is synchronized so this is safe
                nextURI = URIPool.get(True,BLOCK_TIMEOUT)
            except Queue.Empty:
                nextURI = ""
        cli.info('Thread %s: exiting with no more work to do' % self.getName())

#
# This function is the main thread controller. It spawns the 
# maximum number of threads and waits for their completion
#
def thread_controller():
    threadPool = []
    # Start MAX threads and keep track of a reference to them
    if threadCount > URIPool.qsize():
        threadsToSpawn = URIPool.qsize()
    else:
        threadsToSpawn = threadCount
    for x in xrange ( threadsToSpawn ):
        thr = RSYNC_thread()
        thr.setName(x)
        thr.start()
        threadPool.append(thr)
 
    if debug:
        main.info('Number of threads spawned: %d' % len(threadPool))

    notAliveCount = 0
    # while the last count of the dead threads is less than the number spawned
    while notAliveCount < threadsToSpawn :
        notAliveCount = 0
        time.sleep(5)
        for i in threadPool:
            if not i.isAlive():
                notAliveCount = notAliveCount + 1

    if debug:
        main.info('Threads have all closed')

    # Send the RSYNC finished message to the listener
    data = 'RSYNC_DONE'
    #send_to_listener(data)

#
# Create log directories and/or rotate the logs
#
def rotate_logs():
    #create the log directory if it doesn't exist
    if not os.path.exists(logDir):
        os.system("mkdir " + logDir)
    if not os.path.exists(repoDir):
        os.system("mkdir " + repoDir)
    
    #Rotate the main log for rsync_cord
    if os.path.exists(logDir + "/rsync_cord.log.8"):
        os.system("mv -f " + logDir + "/rsync_cord.log.8 " + logDir +
                  "/rsync_cord.log.9")
    if os.path.exists(logDir + "/rsync_cord.log.7"):
        os.system("mv -f " + logDir + "/rsync_cord.log.7 " + logDir +
                  "/rsync_cord.log.8")
    if os.path.exists(logDir + "/rsync_cord.log.6"):
        os.system("mv -f " + logDir + "/rsync_cord.log.6 " + logDir +
                  "/rsync_cord.log.7")
    if os.path.exists(logDir + "/rsync_cord.log.5"):
        os.system("mv -f " + logDir + "/rsync_cord.log.5 " + logDir +
                  "/rsync_cord.log.6")
    if os.path.exists(logDir + "/rsync_cord.log.4"):
        os.system("mv -f " + logDir + "/rsync_cord.log.4 " + logDir +
                  "/rsync_cord.log.5")
    if os.path.exists(logDir + "/rsync_cord.log.3"):
        os.system("mv -f " + logDir + "/rsync_cord.log.3 " + logDir +
                  "/rsync_cord.log.4")
    if os.path.exists(logDir + "/rsync_cord.log.2"):
        os.system("mv -f " + logDir + "/rsync_cord.log.2 " + logDir +
                  "/rsync_cord.log.3")
    if os.path.exists(logDir + "/rsync_cord.log.1"):
        os.system("mv -f " + logDir + "/rsync_cord.log.1 " + logDir +
                  "/rsync_cord.log.2")
    if os.path.exists(logDir + "/rsync_cord.log"):
        os.system("mv -f " + logDir + "/rsync_cord.log " + logDir +
                  "/rsync_cord.log.1")

    #Rotate the main log for rsync_listener
    if os.path.exists(logDir + "/rsync_listener.log.8"):
        os.system("mv -f " + logDir + "/rsync_listener.log.8 " + logDir +
                  "/rsync_listener.log.9")
    if os.path.exists(logDir + "/rsync_listener.log.7"):
        os.system("mv -f " + logDir + "/rsync_listener.log.7 " + logDir +
                  "/rsync_listener.log.8")
    if os.path.exists(logDir + "/rsync_listener.log.6"):
        os.system("mv -f " + logDir + "/rsync_listener.log.6 " + logDir +
                  "/rsync_listener.log.7")
    if os.path.exists(logDir + "/rsync_listener.log.5"):
        os.system("mv -f " + logDir + "/rsync_listener.log.5 " + logDir +
                  "/rsync_listener.log.6")
    if os.path.exists(logDir + "/rsync_listener.log.4"):
        os.system("mv -f " + logDir + "/rsync_listener.log.4 " + logDir +
                  "/rsync_listener.log.5")
    if os.path.exists(logDir + "/rsync_listener.log.3"):
        os.system("mv -f " + logDir + "/rsync_listener.log.3 " + logDir +
                  "/rsync_listener.log.4")
    if os.path.exists(logDir + "/rsync_listener.log.2"):
        os.system("mv -f " + logDir + "/rsync_listener.log.2 " + logDir +
                  "/rsync_listener.log.3")
    if os.path.exists(logDir + "/rsync_listener.log.1"):
        os.system("mv -f " + logDir + "/rsync_listener.log.1 " + logDir +
                  "/rsync_listener.log.2")
    if os.path.exists(logDir + "/rsync_listener.log"):
        os.system("mv -f " + logDir + "/rsync_listener.log " + logDir +
                  "/rsync_listener.log.1")

    #make directories for logs and repository locations
    for direc in dirs:
        d = os.path.dirname(logDir + "/" +  direc)
        if not os.path.exists(d):
            os.makedirs(d)
        d = os.path.dirname(repoDir + "/" + direc)
        if not os.path.exists(d):
            os.makedirs(d)

#
# Function to launch the rsync_listener
#
def launch_listener():
    output = commands.getoutput('ps -A')
    if not 'rsync_listener' in output:
        p = Popen("./rsync_listener %d &> %s/rsync_listener.log" % \
              (portno,logDir), shell=True)
        if debug:
            main.info('rsync_listener pid: %s' % p.pid)
    else:
        main.info('rsync_listener was already running. Continuing execution.')

#
# Function that prints the usage of this script
#
def usage():
    print "rsync_cord [-h -c config] [--help] \n \
            \n \
            Arguments:\n \
            \t-c config\n \
                \t The config file that is to be used\n \
            \t-p port\n \
                \t The port to set the listener running on and communicate with it\n \
            \t-t threadcount\n \
                \t The maximum number of threads to spawn. Default is 8\n \
            \t-d\n \
                \t A debug flag to get extra output in the log file\n \
            \t-h --help\n \
                \t   Shows this help information\n"


#Parse command line args
try:
    opts, args = getopt.getopt(sys.argv[1:], "hdc:p:t:", ["help"])
except getopt.GetoptError, err:
    # print help information and exit:
    print str(err) # will print something like "option -a not recoized"
    usage()
    sys.exit(2)

#Default variables
configFile = ""
portno = 0
threadCount = 8
debug = False

#Parse the options
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-c"):
        configFile = a
    elif o in ("-p"):
        portno = int(a)
    elif o in ("-t"):
        threadCount = int(a)
    elif o in ("-d"):
        debug = True
    else:
        print "unhandled option"
        sys.exit(1)

# If these main two arguments are not present, don't run
if configFile == "":
    print "You must specify the config file"
    sys.exit(1)
if portno == 0:
    print "You must specify the listener port number"
    sys.exit(1)

subprocess.call('source ../envir.setup',shell=True)

#parse config file and get various entries
try:
    configParse = open(configFile, "r")
except:
    print "Check permissions on your config file or that it exists"
    sys.exit(1)

lines = configParse.readlines(10000)
dirs = ""
rsyncDir = ""
repoDir = ""
logDir = ""
sysName = ""
for line in lines:
    if line[:5] == "DIRS=":
        dirs = line[5:]
    elif line[:6] == "RSYNC=":
        rsyncDir = line[6:].strip('\n\";:')
    elif line[:11] == "REPOSITORY=":
        repoDir = line[11:].strip('\n\";:')
    elif line[:5] == "LOGS=":
        logDir = line[5:].strip('\n\";:')

#check for variables in the config file
if dirs == "":
    print "missing DIRS= variable in config"
    sys.exit(1)
if rsyncDir == "":
    print "missing RSYNC= variable in config"
    sys.exit(1)
if repoDir == "":
    print "missing REPOSITORY= variable in config"
    sys.exit(1)
if logDir == "":
    print "missing LOGS= variable in config"
    sys.exit(1)

if dirs.count(',') > 0:
    print "Commas in DIRS variable, Delimiter should be a space."
    sys.exit(1)
if dirs.count(';') > 0:
    print "Semicolons in DIRS variable, delimiter should be a space."
    sys.exit(1)

#Get at each URI in the dirs= element of the config file
URIPool = Queue.Queue(0)
eachDir = (dirs.strip('\"\'').strip('\n').strip('\"\'')).split(' ')

#fill in the queue
dirs = []
for direc in eachDir:
    if not direc == '':
        dirs.append(direc)
        URIPool.put(direc)

#log rotation
rotate_logs()

#Set up logging
logging.basicConfig(level=logging.DEBUG,
	format='%(asctime)-21s %(levelname)-5s %(name)-19s %(message)s',
	datefmt='%d-%b-%Y-%H:%M:%S',
	filename='%s/rsync_cord.log' % (logDir),
	filemode='w')

#Generate the debug logger
main = logging.getLogger('main')
if debug:
    main.info('This will process %d URI\'s from %s' % (len(dirs), configFile))

#launch the listener and the threads
if URIPool.qsize() == 0:
    print "You don't have any URI's to RSYNC with"
    sys.exit(1)
elif URIPool.qsize() == 1:
    main.warn('The URI list only has 1 URI.')
    
launch_listener()
thread_controller()
