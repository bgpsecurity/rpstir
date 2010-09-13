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
import getopt, sys, os, Queue, time, socket, logging, urllib

BLOCK_TIMEOUT = 5
MAXTHREADS = 8
IP_LISTENER = '127.0.0.1'
PORT_LISTENER = 3450

class RSYNC_thread(Thread):
    #The class for handling RSYNC tasks
       
    def run(self):
        try:
            # The python queue is synchronized so this is safe
            nextURI = URIPool.get(True, BLOCK_TIMEOUT)
        except Queue.Empty:
            print "queue empty. %s " % self.getName()
            return
        while not nextURI=="" : #while a URI has been popped
            #build and run the rsync command. This may block for awhile but that is the beauty of the multiple threads. 
            rsyncCom = "rsync -airz --del rsync://%s/ %s/%s > %s/%s.log" %(nextURI, repoDir, nextURI, logDir, nextURI)
            rcode = os.system(rsyncCom)

            #log return code and respond appropriately
            logFile = (logDir + "/rsync_thread_%s.log") % self.getName()
            f = open(logFile, "a")
            f.write( (nextURI + " %d\n") % rcode)
            if rcode == 30:
                #re-run the rsync command
                rcode = os.system(rsyncCom)
                f.write( (nextURI + " 2nd attempt: %d\n") % rcode)
            elif rcode == 35:
                #re-run the rsync command
                rcode = os.system(rsyncCom)
                f.write( (nextURI + " 2nd attempt: %d\n") % rcode)
            f.close()
            
            #notify Listener
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
            s.connect((IP_LISTENER, PORT_LISTENER))
            data = ("%s %s/%s %s/%s.log \n") % (nextURI, repoDir, nextURI, logDir, nextURI)
            bytesSent = s.send(data)
            s.close()

            #get next URI
            try:
                # The python queue is synchronized so this is safe
                nextURI = URIPool.get(True,BLOCK_TIMEOUT)
            except Queue.Empty:
                nextURI = ""

def thread_controller():
    #this function is the main thread controller. It spawns the 
    # maximum number of threads and waits for their completion
    threadPool = []
    # Start MAX threads and keep track of a reference to them
    for x in xrange ( MAXTHREADS ):
        thr = RSYNC_thread()
        thr.setName(x)
        thr.start()
        threadPool.append(thr)
    
    notAliveCount = 0
    # while the last count of the dead threads is less than the number spawned
    while notAliveCount < MAXTHREADS :
        notAliveCount = 0
        time.sleep(5)
        for i in threadPool:
            if not i.isAlive():
                notAliveCount = notAliveCount + 1

    # Send the RSYNC finished message to the listener
    data = 'RSYNC_DONE'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
    s.connect((IP_LISTENER, PORT_LISTENER))
    bytesSent = s.send(data)
    s.close()

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

    #make directories for logs and repository locations
    for direc in dirs:
        d = os.path.dirname(logDir + "/" +  direc)
        if not os.path.exists(d):
            os.makedirs(d)
        d = os.path.dirname(repoDir + "/" + direc)
        if not os.path.exists(d):
            os.makedirs(d)

    #rotate the logs
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

def clean_rsync_logs():
    # this function is supposed to grad each thread log,
    # cat them together into one rsync_cord.log and then
    # delete each thread log
    res = ""
    for x in xrange( MAXTHREADS ):
        fileStr = (" " + logDir + "/rsync_thread_%d.log") % x
        res = res + fileStr

    catStr = "cat " + res + " > " + logDir + "/rsync_cord.log"
    os.system(catStr)

    rmStr = "rm -f " + res
    os.system(rmStr)

def launch_listener():
    os.system(".\rsync_listener %d &" % (PORT_LISTENER)) 

def usage():
    print "rsync_cord [-h -c config] [--help] \n \
            \n \
            Arguments:\n \
            \t-c config\n \
                \t The config file that is to be used\n \
            \t-h --help\n \
                \t   Shows this help information\n"


#Parse command line args
try:
    opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help"])
except getopt.GetoptError, err:
    # print help information and exit:
    print str(err) # will print something like "option -a not recoized"
    usage()
    sys.exit(2)
configFile = ""
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-c"):
        configFile = a
    else:
        assert False, "unhandled option"

if configFile == "":
    assert False, "You must specify the config file"

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
launch_listener()
thread_controller()
clean_rsync_logs()
