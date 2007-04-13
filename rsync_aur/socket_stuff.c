#include "socket_stuff.h"

/**************************************************
 * int tcpsocket(struct write_port *, int portno) *
 *                                                *
 * returns TRUE if write_port structure is        *
 * succesfully setup. False if not.               *
 *                                                *
 * does all of the standard stuff to setup an     *
 * AF_INET, SOCK_STREAM socket, and fills in the  *
 * sockaddr_in structure with the local host from *
 * gethostbyname. This latter part is left in     *
 * so we can latter modify to specify remote host *
 * connections.                                   *
 *                                                *
 * Once everything is setup, it's copied into the *
 * write_port structure and the connect() is      *
 * made using the write_port descriptor.          *
 **************************************************/
int
tcpsocket(struct write_port *wport, int portno)
{
  char hn[256];

  /* set the wport file descriptor to the socket we've created */
  wport->out_desc = socket(AF_INET, SOCK_STREAM, 0);
  if ( (wport->out_desc) < 0) {
    perror("failed to create socket");
    return(FALSE);
  }
                                                              
//  wport->host = gethostbyname("127.0.0.1");                        
  gethostname(hn, 256);
  wport->host = gethostbyname(hn);                        
  if (!(wport->host)) {
    perror("could not create hostent from gethostbyname(\"127.0.0.1\")");
    return(FALSE);
  }

  memset(&(wport->server_addr), '\0', sizeof(struct sockaddr_in));
  memcpy(&(wport->server_addr.sin_addr.s_addr), wport->host->h_addr,
         wport->host->h_length);
  wport->server_addr.sin_family = AF_INET;
  wport->server_addr.sin_port = htons(portno);

  /* set the protocol for this structure. This will be used in 
     our generic write routine to determine if we need {write,send}, or
     sendto */
  wport->protocol = TCP;

  if (connect(wport->out_desc, (const struct sockaddr *)
              &(wport->server_addr), sizeof(wport->server_addr)) < 0) {
    perror("failed on connect()");
    return(FALSE);
  }

  return(TRUE);
}

/**************************************************
 * int udpsocket(struct write_port *, int portno) *
 *                                                *
 * returns TRUE if write_port structure is        *
 * succesfully setup. False if not.               *
 *                                                *
 * does all of the standard stuff to setup an     *
 * AF_INET, SOCK_DGRAM  socket, and fills in the  *
 * sockaddr_in structure with "localhost" from    *
 * gethostbyname. This latter part is left in     *
 * so we can latter modify to specify remote host *
 * connections.                                   *
 *                                                *
 * Once everything is setup, it's copied into the *
 * write_port structure. We have a copy of the of *
 * the sockaddr_in with the server we want to     *
 * send messages to so sendto() can be conveyed   *
 * the correct data.                              *
 **************************************************/
int
udpsocket(struct write_port *wport, int portno)
{

  /* set the file wport desc to the socket we created */      
  wport->out_desc = socket(AF_INET, SOCK_DGRAM, 0);
  if ( (wport->out_desc) < 0) {
    perror("failed to create socket");
    return(FALSE);
  }

  wport->host = gethostbyname("127.0.0.1");
  if (!(wport->host)) {
    perror("could not create hostent from gethostbyname(\"127.0.0.1\")");
    return(FALSE);
  }

  memset(&(wport->server_addr), '\0', sizeof(struct sockaddr_in));
  memcpy(&(wport->server_addr.sin_addr.s_addr), wport->host->h_addr,
         wport->host->h_length);
  wport->server_addr.sin_family = AF_INET;
  wport->server_addr.sin_port = htons(portno);

  /* set the to_length that will be used in sendto() calls */
  wport->to_length = sizeof(struct sockaddr_in);

  /* set the protocol so we know to do sendto rather than 
     {write,send} */
  wport->protocol = UDP;

  return(TRUE);
}

int
outputMsg(struct write_port *wport, char *str, unsigned int len)
{
  int ret;

  (void)printf("Sending %s", str);
  if (wport->protocol == LOCAL) {
    ret = write(wport->out_desc, (const void *)str, len);
    return(ret);
  } else if (wport->protocol == TCP) {
    /* send it */
    ret = write(wport->out_desc, (const void *)str, len);
    return(ret);
  } else if (wport->protocol == UDP) {
      /* send it */
      ret = sendto(wport->out_desc, (const void *)str, len, 0, 
                  (struct sockaddr *)&(wport->server_addr), 
                  wport->to_length);
  } else {
    ret = fprintf(stderr, "unknown protocol specification: %d\n",
                  wport->protocol);
  }
  return(ret);
}
