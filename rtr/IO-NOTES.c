/*

General design (problems):

Spend most of the time in a connection thread blocking on read or write.
When the main thread wants to kill a connection, it calls close and the next read or write
by the connection thread fails, causing the thread to quit.
This needs some kind of idempotent and thread-safe and possibly reentrant guard around close
in case a connection thread is closing itself when main tries to close it or in case a signal to
the connection thread results in a call to close.

This design also makes it hard to handle received error report PDUs when a connection
thread is in a cycle of reading from the database and writing to the router, and to handle
the need to send serial notify PDUs to the router either when read is blocking or at the end
of a cycle of writes.

A possible improvement would be to have one read and one write thread per connection with
a thread-safe queue that main and read can enqueue to and write can dequeue from.

*/



/*
 * Transport module API, each <transport>.so contains these functions and global variables.
 *
 * The non-static module-scope names and types are the API, the variables' values
 * and the function bodies are for example only.
 */

char const * const transport_id = "dummy";
char const * const transport_name = "Dummy Transport";


static struct TransportState {
  everything needed by the transport module between function calls
};

static struct ConnectionState {
  everything needed by the transport module to uniquely identify an individual connection
};


void * initialize_transport(INIConfigSection const * const config_data)
{
  struct TransportState * const transport_state = malloc();

  if (!transport_state)
    goto err;

  if (!parse_config(config_data, transport_state))
    goto err;

  if (!acquire_necessary_resources(transport_state))
    goto err;

  return (void*)transport_state;

err:
  if (transport_state)
    TransportState_free(transport_state);
  return NULL;
}

thread_type run_transport(
  void * const transport_state_voidp,
  void (handle_connection*)(void * handle_connection_arg, void * const connection),
  void * const handle_connection_arg
){
  assert(transport_state_voidp);
  
  struct TransportState * const transport_state = (struct TransportState * const) transport_state_voidp;

  listen for new connections
  run in child thread
  {
    when there's a new connection
    {
      struct ConnectionState * const connection = malloc();
      if (!connection)
        log_and_continue()

      connection->transport_state = transport_state;
      fill in *connection

      handle_connection(handle_connection_arg, (void * const)connection);
    }
    // this block only quits when there's an error or destroy_transport is called
  }

  return child thread;
}

ssize_t read(uint8_t * const buffer, const size_t length, void * const connection_voidp)
{
  assert(buffer);
  assert(connection_voidp);

  struct ConnectionState * const connection = (struct ConnectionState * const)connection_voidp;

  if (transport_specific_read(buffer, length))
    return number of bytes read
  else
    return -1;
}

ssize_t write(uint8_t const * const buffer, const size_t length, void * const connection_voidp)
{
  assert(buffer);
  assert(connection_voidp);

  struct ConnectionState * connection = (struct ConnectionState *)connection_voidp;

  if (transport_specific_write(buffer, length))
    return number of bytes written
  else
    return -1
}

void close(void * const connection_voidp)
{
  if (!connection_voidp)
    return;

  struct ConnectionState * connection = (struct ConnectionState *)connection_voidp;

  transport_specific_close();

  ConnectionState_free(connection);
}

int log_prefix_snprint(char * const buffer, const size_t max_length; void const * const connection_voidp)
{
  assert(buffer);
  assert(connection_voidp);

  struct ConnectionState * connection = (struct ConnectionState *)connection_voidp;

  return snprintf(buffer, max_length, some format string, some information from connection, ...);
}

void destroy_transport(void * const transport_state_voidp)
{
  assert(transport_state_voidp);

  struct TransportState * const transport_state = (struct TransportState * const) transport_state_voidp

  stop listening for connections

  TransportState_free(transport_state);
}



/*
 * Server code
 */

// TODO: figure out what to do when doUpdate finishes updating the database (i.e. how to send Serial Notify PDUs)

static struct TransportThreadData {
  module_type module;
  thread_type thread;
  void * data;
};

static struct ConnectionThreadData {
  TransportThreadData * transport;
  thread_type thread;
  void * data;
};

bool initialize(config_file, container of (TransportThreadData) transports)
{
  if (!parse config file)
    return false;

  ...

  foreach const INIConfigSection transport_section
  {
    open transport_section.module_name .so
    void * const transport_data = module::initialize_transport(transport_section);
    if (transport_data)
    {
      TransportThreadData transport;
      transport.module = module;
      transport.thread = INVALID;
      transport.data = transport_data;
      add transport to transports
    }
    else
    {
      log error
      return false;
    }
  }

  ...

  return true;
}

void quit(container of (TransportThreadData) transports, container of (ConnectionThreadData) connections)
{
  foreach connection
  {
    connection.transport->module::close(connection.data);
  }

  foreach transport
  {
    transport.module::destroy_transport(transport.data);
  }

  foreach connection
  {
    wait(connection.thread);
  }

  foreach transport
  {
    wait(transport.thread);
  }
}

void handle_connection(void * handle_connection_arg, void * const connection_data)
{
  assert(handle_connection_arg);

  transport, connections = grab stuff from handle_connection_arg

  struct ConnectionThreadData connection;
  connection.transport = transport;
  connection.data = connection_data;
  connection.thread = new thread(
  {
    do stuff, including logging, reading, writing, and eventually closing connection
  })

  add connection to connections
}

bool run(container of (TransportThreadData) transports)
{
  container of (ConnectionThreadData) connections;

  on quit signals, call quit(transports, connections)

  foreach transport
  {
    transport.thread = transport.module::run_transport(transport.data, &handle_connection, pair of transport and connections);

    if (!transport.thread)
    {
      log error
      quit(transports, connections);
      return false;
    }
  }

  return true;
}

main ()
{
  container of (TransportThreadData) transports;

  initialize(config_data, transports)

  run(transports)

  sleep.. or something
}
