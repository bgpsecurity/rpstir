/*
  This file contains some notes on how to implement a program to maintain
  the RPKI file repository cache of multiple remote rsync repositories.
  It tries to do all network operations in parallel. It also tries to be
  as resistant to concurrency and crashing issues as possible.

  NOTE: While this maintains a valid repository at all times, there
  is currently no mechanism provided to ensure to other RPKI programs
  that they are accessing a currently valid version of the repository.
  E.g. this program knows whether the valid version of a file is in the
  "current" or "old" directory, but it doesn't expose any API for other
  programs to get that information.
*/

#define STATE_DIR "rsync/state"
#define REPO_DIR "REPOSITORY"
#define LOG_DIR "LOGS"

typedef enum _dir_type {
  DIR_CUR,
  DIR_OLD;
} dir_type;

char[][] dir_type_names = {
  "cur", // DIR_CUR
  "old", // DIR_OLD
};

typedef enum _log_type {
  LOG_CUR,
  LOG_ARCHIVE;
} log_type;

char[][] log_type_names = {
  "cur", // LOG_CUR
  "archive", // LOG_ARCHIVE
};

typedef struct _thread_state {
  URI rsync_uri;
  dir_type aur_done;
  dir_type rsync_done;
  log_type log_done;
  char *state_path;
} thread_state;

thread_state * new_thread_state()
{
  malloc
  rsync_uri = NULL
  state_path = NULL
  return
}

free_thread_state(thread_state * statep)
{
  ...
}

set_state(const thread_state * statep) // warn if return value unused?
{
  char * path;
  if (statep->path == NULL)
    path = cat(getenv("RPKI_ROOT"), "/", STATE_DIR, "/thread", get_globally_unique_thread_id());
  else
    path = statep->state_path;

  if (statep->rsync_uri == NULL)
  {
    unlink(path); // and check for errors
    // sync?
  }
  else
  {
    fd = open(cat(path, ".new"), for writing); // and check for errors
    truncate(fd);
    size_t len = serialize(statep, buffer); // and check for errors
    write(fd, buffer, len); // and check for errors
    sync(fd);
    close(fd);
    rename(cat(path, ".new"), path);
    // sync?
  }
}

get_state(thread_state *statep)
{
  assert(statep != NULL);
  if (statep->state_path && (fd = open(statep->state_path, for reading)))
  {
    size_t len = read(fd, buffer, MAXLEN); // and check for errors
    unserialize(statep, buffer, len); // and check for errors
  }
  else
  {
    statep->rsync_uri = NULL;
  }
  if (fd) close(fd);
}

get_dir_path(dir_type dtype, URI uri, char *buffer, size_t maxlen)
{
  buffer = cat(getenv("RPKI_ROOT"), "/", REPO_DIR, "/", dir_type_names[dtype], "/", normalize(uri));
}

get_log_path(log_type ltype, URI uri, char *buffer, size_t maxlen)
{
  buffer = cat(getenv("RPKI_ROOT"), "/", LOG_DIR, "/", log_type_names[ltype], "/", normalize(uri));
  if (ltype == LOG_ARCHIVE)
  {
    buffer = cat(buffer, "-", date and time, ".", host name, ".", random number);
  }
  buffer = cat(buffer, ".log");
}

// PRECONDITION: recover_all() has finished successfully, i.e. cur_path is in good shape and the log is archived
start_directory_update(thread_state *statep)
{
  get_dir_path(DIR_OLD, statep->rsync_uri, old_path, maxlen);
  get_dir_path(DIR_CUR, statep->rsync_uri, cur_path, maxlen);

  rm -rf old_path
  hardlink copy cur_path to old_path
  sync(old_path)
  statep->aur_done = DIR_OLD;
  statep->rsync_done = DIR_OLD;
  statep->log_done = LOG_ARCHIVE;
  set_state(statep);

  assert(statep->rsync_done == DIR_OLD);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_ARCHIVE);
}

run_rsync(thread_state *statep)
{
  assert(statep->rsync_done == DIR_OLD);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_ARCHIVE);

  get_dir_path(DIR_CUR, statep->rsync_uri, cur_path, maxlen);
  get_log_path(LOG_CUR, statep->rsync_uri, logfile, maxlen);

  call rsync to update cur_path from statep->rsync_uri, being aware of hardlinks and logging to logfile
  sync(cur_path)
  sync(logfile)
  statep->rsync_done = DIR_CUR;
  statep->log_done = LOG_CUR;
  set_state(statep);

  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_CUR);
}

run_aur(thread_state *statep)
{
  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_CUR);

  get_log_path(LOG_CUR, statep->rsync_uri, logfile, maxlen);

  run rsync_aur on logfile
  flush rcli
  statep->aur_done = DIR_CUR;
  set_state(statep);

  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_CUR);
  assert(statep->log_done == LOG_CUR);
}

archive_log(thread_state *statep)
{
  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_CUR);
  assert(statep->log_done == LOG_CUR);

  get_log_path(LOG_CUR, statep->rsync_uri, cur_file, maxlen);
  get_log_path(LOG_ARCHIVE, statep->rsync_uri, archive_file, maxlen);

  ret = rename(cur_file, archive_file));
  if (ret is success)
  {
    sync(archive_file);
  }
  else if (ret indicates cur_file didn't exist)
  {
    /*
      This isn't an error, because this can only happen if somebody is messing
      with the filesystem, in which case we're in trouble anyway, or if this
      is during a recovery, in which case the program crashed between archiving
      the log and setting log_done to LOG_ARCHIVE.
    */
    log warning
  }
  else
  {
    log error
    exit
  }

  statep->log_done = LOG_ARCHIVE;
  set_state(statep);

  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_CUR);
  assert(statep->log_done == LOG_ARCHIVE);
}

update_directory(thread_state *statep)
{
  start_directory_update(statep);

  run_rsync(statep);

  run_aur(statep);

  archive_log(statep);
}

recover(thread_state *statep)
{
  if (statep->rsync_uri == NULL)
    return;

  if (statep->rsync_done == DIR_OLD)
  {
    // don't try to resume an aborted rsync, just roll-back the changes

    if (statep->aur_done != DIR_OLD)
    {
      log error
      exit
    }

    if (statep->log_done != LOG_ARCHIVE)
    {
      log error
      exit
    }

    get_dir_path(DIR_OLD, statep->rsync_uri, old_path, maxlen);
    get_dir_path(DIR_CUR, statep->rsync_uri, cur_path, maxlen);
    get_log_path(LOG_CUR, statep->rsync_uri, logfile, maxlen);
    rm -r cur_path
    rm logfile
    hardlink copy old_path to cur_path
    sync(cur_path);
    statep->aur_done = DIR_CUR;
    statep->rsync_done = DIR_CUR;
    set_state(statep);

    goto done;
  }

  if (statep->aur_done == DIR_OLD)
  {
    // try to re-run an aborted AUR
    // NOTE: this relies on AUR being an idempotent operation

    assert(statep->rsync_done == DIR_CUR); // assert because of the above if-statement

    if (statep->log_done != LOG_CUR)
    {
      log error
      exit
    }

    run_aur(statep);
  }

  if (statep->log_done == LOG_CUR)
  {
    archive_log(statep);
  }

done:
  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_CUR);
  assert(statep->log_done == LOG_ARCHIVE);
}

recover_all()
{
  thread_state *statep = new_thread_state();

  for each file in cat(getenv("RPKI_ROOT"), "/", STATE_DIR)
  {
    if (!(file begins with "thread-"))
      continue;

    statep->state_path = file;

    get_state(statep);

    recover(statep);

    statep->state_path = NULL;

    unlink(file);
  }

  free_thread_state(statep);
}

listen_thread(void *uri_queue_voidp)
{
  ThreadSafeQueue *uri_queue = (ThreadSafeQueue *)uri_queue_voidp;

  ...
  {
    ...
    uri_queue->enqueue(uri);
  }

  uri_queue->enqueue_all(NULL);
}

rsync_thread(void *uri_queue_voidp)
{
  ThreadSafeQueue *uri_queue = (ThreadSafeQueue *)uri_queue_voidp;
  thread_state *statep = new_thread_state();

  while ((statep->rsync_uri = uri_queue->dequeue()) != NULL)
  {
    update_directory(statep);
  }

  free_thread_state(statep);
}

main()
{

  if (!lock(cat(getenv("RPKI_ROOT"), "/", STATE_DIR, "/main.lock")))
  {
     log error message that main is already running and delete lock file if it's not running
     exit
  }

  trap signals and on exit call unlock(cat(getenv("RPKI_ROOT"), "/", STATE_DIR, "/main.lock"))

  recover_all();

  ThreadSafeQueue *uri_queue = new_queue();

  thread listener = start_thread(listen_thread, (void*)uri_queue);
  thread rsyncs[num_threads];
  for (int i = 0; i < num_threads; ++i)
  {
    rsyncs[i] = start_thread(rsync_thread, (void*)uri_queue);
  }

  listener.join();
  for (int i = 0; i < num_threads; ++i)
  {
    rsyncs[i].join();
  }
}
