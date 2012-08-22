/**@file rsync_listener.c
 *
 * @brief Starts a simple TCP server and listens for incoming connections
 * from rsync_cord.py. Once a connection is established a retrieval log
 * file name and the local file cache name are sent, parsed, and queued.
 * Eventually all files are dequeued and passed to the log_parser and updated
 * in the database.
 *
 * @author Ryan Caloras
 * @date 9/8/2010
 * @bugs None known
 */

#include "rsync_listener.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "csapp.h"
#include "signal.h"
#include "util/logutils.h"

/*
 * The head of the queue
 */
static rsync_node *head = NULL;
/*
 * The tail od the queue
 */
static rsync_node *tail = NULL;
/*
 * The worker thread to accept connections
 */
static pthread_t tid;
static int port_number = DEFAULT_PORT;
static pthread_mutex_t queue_mutex;
static pthread_cond_t rsync_cv;
static const char *rsync_listener_logfile = "rsync_listener.log";
time_t rawtime;

int main(
    int argc,
    char *argv[])
{
    int rc = 0;
    time(&rawtime);

    /*
     * Setup our file logging 
     */
    log_init(rsync_listener_logfile, "r_listener", LOG_DEBUG, LOG_DEBUG);
    log_msg(LOG_INFO, "======= rsync_listener STARTED =======");

    Signal(SIGHUP, sighup_handler);
    Signal(SIGTERM, sighup_handler);
    /*
     * Initialize our condition variable and mutex
     */
    pthread_mutex_init(&queue_mutex, NULL);
    pthread_cond_init(&rsync_cv, NULL);

    /*
     * Check if we have an argument for the port
     */
    if (argc > 2)
    {
        fprintf(stderr, "usage %s <port number>\n", argv[0]);
        exit(1);
    }
    if (argc == 2)
    {
        if (!(port_number = atoi(argv[1])))
        {
            fprintf(stderr, "usage %s <port number>\n", argv[0]);
            exit(1);
        }
    }
    /*
     * Spawn our thread to run the server
     */
    if ((rc = pthread_create(&tid, NULL, recv_rsync_conns, NULL)) != 0)
    {
        log_msg(LOG_ERR, "Error during initial thread creation: rc= %d", rc);
        log_close();
        return rc;
    }

    while (1)
    {
        int err_flag = 0;
        pthread_mutex_lock(&queue_mutex);
        rsync_node *parse_node;
        while ((parse_node = dequeue()) == NULL)
        {
            /*
             * Nothing in the queue for us to parse so we deschedule
             */
            pthread_cond_wait(&rsync_cv, &queue_mutex);
        }
        pthread_mutex_unlock(&queue_mutex);
        /*
         * parse out the uri, repository location, and log location
         */
        char *parse_me = parse_node->payload;
        parse_me = strtok(parse_me, "\r");

        /*
         * If this was just a connection test
         */
        if (!parse_me)
        {
            free(parse_node->payload);
            free(parse_node);
            continue;
        }

        /*
         * When we encounter this message it should be appended to the end of
         * the queue
         */
        if (!strcmp(parse_me, "FINISH_QUEUE_EXIT"))
        {
            log_msg(LOG_INFO, "Received FINISH_QUEUE_EXIT");
            free(parse_node->payload);
            free(parse_node);
            break;
        }
        /*
         * Signals the end of an instance of rsync_cord.py.
         */
        if (!strcmp(parse_me, "RSYNC_DONE"))
        {
            log_msg(LOG_INFO,
                    "Received RSYNC_DONE (end of an instance of rsync_cord.py)");
            log_flush();
            free(parse_node->payload);
            free(parse_node);
            continue;
        }
        char *uri,
           *rep_loc,
           *log_loc;
        FILE *logfile;
        FILE *reposit;

        // printf("About to parse a node! payload: %s\n",parse_me);
        /*
         * Args should be passed with a space after each " arg1 arg2 arg3 "
         */
        uri = strtok(parse_me, " ");
        rep_loc = strtok(NULL, " ");
        log_loc = strtok(NULL, " ");

        /*
         * Error check what we've been passed before we generate a command for 
         * rsync_aur. First check if all three arguments are not null, then
         * test to open the files
         */
        if ((uri == NULL) || (log_loc == NULL) || (rep_loc == NULL))
        {
            err_flag = NULL_ARGS_ERR;
            log_msg(LOG_ERR,
                    "One or more variables parsed out was null: uri %s, log_loc %s, rep_loc %s",
                    uri, log_loc, rep_loc);
        }
        else if (!(logfile = fopen(log_loc, "r")))
        {
            err_flag = OPEN_LOG_ERR;
            log_msg(LOG_ERR,
                    "Failed to open logfile: log_loc %s. Probably incorrect filename.",
                    log_loc);
        }
        else if (!(reposit = fopen(rep_loc, "r")))
        {
            err_flag = OPEN_REPOSITORY_ERR;
            log_msg(LOG_ERR,
                    "Failed to open repository: rep_loc %s. Probably incorrect filename.",
                    rep_loc);
        }

        /*
         * just opened them to check existence, we can close them now
         */
        if (logfile)
        {
            fclose(logfile);
            logfile = NULL;
        }
        if (reposit)
        {
            fclose(reposit);
            reposit = NULL;
        }

        /*
         * If we haven't detected any problems thus far with our inuput, then
         * we'll generate and make the call to rsync_aur
         */
        if (!err_flag)
        {
            int status;
            char path[MAXREAD];
            char command[MAXREAD];
            int pipefd[2];
            pid_t cpid;
            /*
             * Initilize buffers to be safe due to issues with OpenBSD
             */
            memset(path, '\0', MAXREAD);
            memset(command, '\0', MAXREAD);

            snprintf(command, sizeof(command), "%s/bin/rpki-rsync/rsync_aur",
                     getenv("RPKI_ROOT"));

            if (pipe(pipefd) != 0)
            {
                err_flag = POPEN_PARSER_ERR;
                goto no_subproc;
            }

            cpid = fork();
            if (cpid == -1)
            {
                err_flag = POPEN_PARSER_ERR;
                goto no_subproc;
            }
            else if (cpid == 0)
            {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                log_msg(LOG_DEBUG, "%s -s -t %s -f %s -d %s", command,
                        getenv("RPKI_PORT"), log_loc, rep_loc);
                log_flush();
                execl(command, command, "-s", "-t", getenv("RPKI_PORT"), "-f",
                      log_loc, "-d", rep_loc, (const char *)NULL);
                perror("execl()");
                exit(EXIT_FAILURE);     // execl shouldn't return
            }

            close(pipefd[1]);
            FILE *fp = fdopen(pipefd[0], "r");

            /*
             * Read the response from the parser
             */
            while (fgets(path, MAXREAD, fp) != NULL)
            {
                log_msg(LOG_DEBUG, "rsync_aur output: %s", path);
            }
            fclose(fp);
            wait(&status);
            log_msg((status == 0) ? LOG_INFO : LOG_ERR,
                    "Process ended with termination status %d (command = %s -s -t %s -f %s -d %s)\n",
                    status, command, getenv("RPKI_PORT"), log_loc, rep_loc);
            log_flush();
        }
        /*
         * Clean up and log some stuff if needed
         */
      no_subproc:
        if (err_flag)
        {
            log_msg(LOG_ERR, " Error Code: %d. Continuing.\n", err_flag);
            log_flush();
        }

        free(parse_node->payload);
        free(parse_node);
    }
    log_close();
    return 0;
}

/** @brief recv_rsync_conns Runs a single thread which repeatedly accpets connections from rsync_cord.py.
 *  For each connection, a line of length MAXREAD is robustly read, memory is malloced and used for
 *  storing the line, a new rsync_node is created for it, and finally that node is queued. A condition
 *  variable is signlaed for a possible thread waiting to read the contents of the queue.
 */
void *recv_rsync_conns(
    void *unused)
{
    (void)unused;

    int listenfd,
        connfd;
    unsigned int clientlen;
    struct sockaddr_in clientaddr;
    listenfd = Open_listenfd(port_number);
    clientlen = sizeof(clientaddr);

    /*
     * Ignore SIGPIPE it might come up later
     */
    Signal(SIGPIPE, SIG_IGN);

    /*
     * Continually accept connections and create new nodes to parse later
     */
    while (1)
    {
        connfd = Accept(listenfd, (SA *) & clientaddr, &clientlen);
        rio_t rio;
        rsync_node *new_node;
        if (!(new_node = malloc(sizeof(rsync_node))))
        {
            log_msg(LOG_ERR,
                    "malloc error for new node during recv_rsync_conns");
            return NULL;
        }
        char *payload;
        if (!(payload = calloc(MAXREAD, sizeof(char))))
        {
            log_msg(LOG_ERR,
                    "malloc error for payload during recv_rsync_conns");
            return NULL;
        }

        rio_readinitb(&rio, connfd);
        rio_readlineb(&rio, payload, MAXREAD);
        log_msg(LOG_DEBUG, "From rsync_cord: %s", payload);
        /*
         * Setup our rsync_node, queue it up, then signal the parser to wake
         * up because there is work for it
         */
        new_node->payload = payload;
        new_node->next = NULL;
        pthread_mutex_lock(&queue_mutex);
        enqueue(new_node);
        pthread_cond_signal(&rsync_cv);
        pthread_mutex_unlock(&queue_mutex);
        Close(connfd);
    }
}

void sighup_handler(
    int sig)
{
    (void)sig;
    pthread_mutex_lock(&queue_mutex);
    pthread_cancel(tid);
    rsync_node *node;
    while ((node = dequeue()) != NULL)
    {
        free(node->payload);
        free(node);
    }
    pthread_mutex_unlock(&queue_mutex);
    log_msg(LOG_INFO, "Rsync_listener queue cleared, now terminating...");
    log_close();
    exit(0);
}

void enqueue(
    rsync_node * node)
{
    if (head == NULL)
    {
        head = node;
        tail = node;
        return;
    }
    else
    {
        tail->next = node;
        tail = node;
        node->next = NULL;
        return;
    }
}

rsync_node *dequeue(
    )
{
    if (head == NULL)
    {
        return NULL;
    }
    /*
     * If there is one node queued
     */
    if (head == tail)
    {
        tail = NULL;
    }
    rsync_node *ret = head;
    head = head->next;
    return ret;
}
