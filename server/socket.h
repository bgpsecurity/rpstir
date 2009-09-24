/*************************
 * The code for setting up socket connections between the server
 *  and the clients
 *************************/

/******
 * Get a server side socket, currently allowing just one client
 * Returns -1 if error
 ******/
int getServerSocket(void);


/******
 * Get a client side socket
 * Argument hostname: host name of the server
 * Returns -1 if error
 ******/
int getClientSocket(char *hostName);
