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

bool run_transport(
  void * const transport_state_voidp,
  void (handle_connection*)(void * handle_connection_arg, void * const connection),
  void * const handle_connection_arg
){
  assert(transport_state_voidp);
  
  struct TransportState * const transport_state = (struct TransportState * const) transport_state_voidp;

  listen for new connections
  when there's a new connection
  {
    struct ConnectionState * const connection = malloc();
    if (!connection)
      log_and_continue()

    connection->transport_state = transport_state;
    fill in *connection

    handle_connection(handle_connection_arg, (void * const)connection);
  }
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
