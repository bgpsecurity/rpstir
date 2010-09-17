/**@file rsync_listener.c
 ** ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Ryan Caloras
 *
 * ***** END LICENSE BLOCK *****
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "rsync_listener.h"
#include "csapp.h"

/*The head of the queue*/
static rsync_node* head = NULL;
/*The tail od the queue*/
static rsync_node* tail = NULL;

static int port_number = DEFAULT_PORT;

pthread_mutex_t queue_mutex;
pthread_cond_t rsync_cv;

int main (int argc, char *argv [])
{
	int rc = 0;
	/*Initialize our condition variable and mutex*/
	pthread_mutex_init(&queue_mutex, NULL);
	pthread_cond_init (&rsync_cv, NULL);

	/*Check if we have an argument for the port*/
	if(argc > 2){
		fprintf(stderr, "usage %s <port number>\n", argv[0]);
		exit(1);
	}
	if(argc == 2){
		if(!(port_number = atoi(argv[1]))){
			fprintf(stderr, "usage %s <port number>\n", argv[0]);
			exit(1);
			}
	}
	pthread_t tid;


	/*Spawn our thread to run the server*/
	if((rc = pthread_create(&tid, NULL,recv_rsync_conns,NULL)) != 0){
		printf("Error during initial thread creation: rc= %d",rc);
		return rc;
	}

	while(1){	
		pthread_mutex_lock(&queue_mutex);
		rsync_node* parse_node;
		while((parse_node = dequeue()) == NULL){
		/*Nothing in the queue for us to parse so we deschedule*/
			pthread_cond_wait(&rsync_cv, &queue_mutex);
		} 
		pthread_mutex_unlock(&queue_mutex);
		/*parse out the uri, repository location, and log location*/
		char *parse_me = parse_node->payload;
		
		/*If we're done receiving rsyncs we'll get an RSYNC_DONE
		  signal from rsync_cord.py. But first remove
		  the carraige return on the sting.*/
		parse_me = strtok(parse_me,"\r");
		if(!strcmp(parse_me,"RSYNC_DONE")){
			free(parse_node->payload);
			free(parse_node);
			break;
		}
		char *uri, *rep_loc, *log_loc;
		printf("About to parse a node! payload: %s\n",parse_me);

		/*Args should be passed with a space after each " arg1 arg2 arg3 "*/
		uri = strtok(parse_me," ");
		rep_loc = strtok( NULL," ");
		log_loc = strtok(NULL," ");
	
		//printf("uri %s, log_loc %s, rep_loc %s", uri, log_loc, rep_loc);
		
		/*Generate a command line string which will execute rsync_aur
		  once fed to another shell by popen*/
		FILE *fp;
		int status;
		char path[MAXREAD];
		char command[MAXREAD];
		/*Initilize buffers to be safe due to issues with OpenBSD*/
		memset(path,'\0',MAXREAD);
		memset(command,'\0',MAXREAD);

		
		snprintf(command, MAXREAD,"%s/rsync_aur/rsync_aur -t %s -f %s -d %s",getenv("RPKI_ROOT"), getenv("RPKI_PORT"), log_loc, rep_loc);
		printf("%s\n",command);

		/*popen should spawn a new command line and invoke rsync_aur from there*/
		fp = popen(command, "r");
		if (fp == NULL){
	    /* Handle error */;
			printf("Error forking process and starting Parser..exiting. Status = %d", pclose(fp));
			return POPEN_PARSER_ERR;
		}

		/*Read the response from the parser*/
		while (fgets(path, MAXREAD, fp) != NULL)
			printf("%s", path);
		status = pclose(fp);

		//Clean up and log some stuff if needed
		free(parse_node->payload);
		free(parse_node);
	}
	return 0;
}
/** @brief recv_rsync_conns Runs a single thread which repeatedly accpets connections from rsync_cord.py.
 *  For each connection, a line of length MAXREAD is robustly read, memory is malloced and used for
 *  storing the line, a new rsync_node is created for it, and finally that node is queued. A condition
 *  variable is signlaed for a possible thread waiting to read the contents of the queue.
 */
void *recv_rsync_conns()
{

	int listenfd, connfd;
	unsigned int clientlen;
	struct sockaddr_in clientaddr;
	listenfd = Open_listenfd(port_number);
	clientlen = sizeof(clientaddr);

	/*Ignore SIGPIPE it might come up later*/
	Signal(SIGPIPE,SIG_IGN);

	/*Continually accept connections and create new nodes to parse later*/
	while(1){
		connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
		rio_t rio;
		rsync_node* new_node;
		if(!(new_node = malloc(sizeof(rsync_node)))){
			fprintf(stderr, "malloc error for new node during recv_rsync_conns");
			return NULL;
		}
		char* payload;
		if(!(payload = calloc(MAXREAD, sizeof(char)))){
			fprintf(stderr, "malloc error for payload during recv_rsync_conns");
		return NULL;
		}

		rio_readinitb(&rio, connfd);
		rio_readlineb(&rio, payload, MAXREAD);
		printf("contents of buf %s",payload);;
		/*Setup our rsync_node, queue it up, then signal the
		  parser to wake up because there is work for it*/
		new_node->payload = payload;
		new_node->next = NULL;
		pthread_mutex_lock(&queue_mutex);
		enqueue(new_node);
		pthread_cond_signal(&rsync_cv);
		pthread_mutex_unlock(&queue_mutex);
		Close(connfd);
	}
}

void enqueue(rsync_node* node)
{
	if(head == NULL){
		head = node;
		tail = node;
		return;
	}
	else{
		tail->next = node;
		tail = node;
		node->next = NULL;
		return;
	}
}
rsync_node* dequeue()
{
	if(head == NULL){
		return NULL;
	}
	/*If there is one node queued*/
	if(head == tail)
	{
		tail = NULL;
	}	
	rsync_node* ret = head;
	head = head->next;
	return ret;
}
