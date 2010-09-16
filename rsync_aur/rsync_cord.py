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
import getopt, sys, os, Queue, time, socket, subprocess, logging

BLOCK_TIMEOUT = 1
IP_LISTENER = '127.0.0.1'

def send_to_listener(data):
    #This needs a lot of error checking
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
    s.connect((IP_LISTENER, portno))
    bytesSent = s.send(data)
    s.close()


class RSYNC_thread(Thread):
    #The class for handling RSYNC tasks
       
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

            #build and run the rsync command. This may block for awhile but that
            #is the beauty of the multiple threads.
            rsyncCom = "rsync -airz --del --timeout=10 rsync://%s/ %s/%s 1> %s/%s.log" \
                       % (nextURI, repoDir, nextURI, logDir, nextURI)

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
                data = ("%s %s/%s %s/%s.log") % \
                              (nextURI, repoDir, nextURI, logDir, nextURI)
                              
                send_to_listener(data)

            #get next URI
            try:
                # The python queue is synchronized so this is safe
                nextURI = URIPool.get(True,BLOCK_TIMEOUT)
            except Queue.Empty:
                nextURI = ""
        cli.info('Thread %s: exiting with no more work to do' % self.getName())

def thread_controller():
    #this function is the main thread controller. It spawns the 
    # maximum number of threads and waits for their completion
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
    send_to_listener(data)

def sanity_check_and_rotate_logs():
    #check for variables in the config file
    if dirs == "":
        assert False, "missing DIRS= variable in config"
    if rsyncDir == "":
        assert False, "missing RSYNC= variable in config"
    if repoDir == "":
        assert False, "missing REPOSITORY= variable in config"
    if logDir == "":
        assert False, "missing LOGS= variable in config"

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

    #rotate the logs for the URI's
    for direc in dirs:
        startPath = logDir + "/" + direc
        if os.path.exists(startPath + ".log.8"):
            os.system("mv -f " + startPath + ".log.8 " + startPath + ".log.9")
        if os.path.exists(startPath + ".log.7"):
            os.system("mv -f " + startPath +  ".log.7 " + startPath + ".log.8")
        if os.path.exists(startPath + ".log.6"):
            os.system("mv -f " + startPath +  ".log.6 " + startPath + ".log.7")
        if os.path.exists(startPath + ".log.5"):
            os.system("mv -f " + startPath +  ".log.5 " + startPath + ".log.6")
        if os.path.exists(startPath + ".log.4"):
            os.system("mv -f " + startPath + ".log.4 " + startPath + ".log.5")
        if os.path.exists(startPath + ".log.3"):
            os.system("mv -f " + startPath + ".log.3 " + startPath + ".log.4")
        if os.path.exists(startPath + ".log.2"):
            os.system("mv -f " + startPath + ".log.2 " + startPath + ".log.3")
        if os.path.exists(startPath + ".log.1"):
            os.system("mv -f " + startPath + ".log.1 " + startPath + ".log.2")
        if os.path.exists(startPath + ".log"):
            os.system("mv -f " + startPath + ".log " + startPath + ".log.1")

def launch_listener():
    p = Popen("./rsync_listener %d &> %s/rsync_listener.log" % \
              (portno,logDir), shell=True)
    if debug:
        main.info('rsync_listener pid: %s' % p.pid)
    

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
        assert False, "unhandled option"

if configFile == "":
    assert False, "You must specify the config file"
if portno == 0:
    assert False, "You must specify the listener port number"

subprocess.call('../envir.setup',shell=True)

#parse config file and get various entries
configParse = open(configFile, "r")
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

#Get at each URI in the dirs= element of the config file
URIPool = Queue.Queue(0)
eachDir = (dirs.strip('\"').strip('\n').strip('\"')).split(' ')

#fill in the queue
dirs = []
for direc in eachDir:
    dirs.append(direc)
    URIPool.put(direc)

sanity_check_and_rotate_logs()

logging.basicConfig(level=logging.DEBUG,
	format='%(asctime)-21s %(levelname)-5s %(name)-19s %(message)s',
	datefmt='%d-%b-%Y-%H:%M:%S',
	filename='%s/rsync_cord.log' % (logDir),
	filemode='w')
if debug:
    main = logging.getLogger('main')
    main.info('Parsing the dirs out of the config file')
    main.info('This will process %d URI\'s from %s' % (len(dirs), configFile))
     
launch_listener()
thread_controller()
