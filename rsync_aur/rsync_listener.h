/**@file rsync_listener.h
 *
 * ***** BEGIN LICENSE BLOCK *****
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
 * @author Ryan Caloras
 * @date 9/9/10
 * @bugs None known
 */
#ifndef _RSYNC_LISTENER_H
#define _RSYNC_LISTENER_H 

#define DEFAULT_PORT 3450
#define POPEN_PARSER_ERR -1
#define NULL_ARGS_ERR -2
#define OPEN_LOG_ERR -3
#define OPEN_REPOSITORY_ERR -4
#define MAXREAD 2048


typedef struct rsync_node{
	/*The address of the retrieval log and name file cache. Still in one chunk to parse.*/
	char* payload;
	/*Pointer to the next node in the queue*/
	struct rsync_node* next;
} rsync_node;
	
rsync_node* dequeue(void);
void create_new_log(void);
void *recv_rsync_conns(void);
void sighup_handler(int sig);
void enqueue(rsync_node* node);
#endif /* _RSYNC_LISTENER_H*/
