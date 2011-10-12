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

typedef struct _URI_attempt {
  URI *uri;
  size_t attempt;
  time_t next_attempt;
} URI_attempt;

URI_attempt * new_URI_attempt(URI *uri)
{
  URI_attempt *ret = malloc
  URI *uri_copy = malloc
  copy uri to uri_copy
  ret->uri = uri_copy;
  ret->attempt = 0;
  ret->next_attempt = TIME_MIN
  return ret
}

free_URI_attempt(URI_attempt *uri_attemptp)
{
  if (uri_attemptp)
  {
    if (uri_attemptp->uri)
    {
      free uri_attemptp->uri
    }
    free uri_attemptp
  }
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

bool run_rsync(thread_state *statep)
{
  assert(statep->rsync_done == DIR_OLD);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_ARCHIVE);

  get_dir_path(DIR_CUR, statep->rsync_uri, cur_path, maxlen);
  get_log_path(LOG_CUR, statep->rsync_uri, logfile, maxlen);

  call rsync to update cur_path from statep->rsync_uri, being aware of hardlinks and logging to logfile
  if (rsync failed)
  {
    rm -r cur_path
    rm logfile
    hardlink copy old_path to cur_path
    sync(cur_path);
    statep->aur_done = DIR_CUR;
    statep->rsync_done = DIR_CUR;
    set_state(statep);
    return false;
  }

  sync(cur_path)
  sync(logfile)
  statep->rsync_done = DIR_CUR;
  statep->log_done = LOG_CUR;
  set_state(statep);

  assert(statep->rsync_done == DIR_CUR);
  assert(statep->aur_done == DIR_OLD);
  assert(statep->log_done == LOG_CUR);
  return true;
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

  ret = rename(cur_file, archive_file);
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

bool update_directory(thread_state *statep)
{
  start_directory_update(statep);

  if (!run_rsync(statep))
    return false;

  run_aur(statep);

  archive_log(statep);

  return true;
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

bool conflicts_with_currently_processing(ThreadSafeSet *currently_processing, URI uri)
{
  assert(calling thread has a lock on currently_processing);
  return (uri is equal to, a descendent of, or an ancestor of any member of currently_processing);
}

bool ready_for_next_attempt(URI_attempt *uri_attemptp)
{
  return (now >= uri_attemptp->next_attempt)
}

/** @return the next URI_attempt to try, or NULL if there's nothing to be tried at this time */
URI_attempt * choose_next_uri(ThreadSafeSet *currently_processing, some_container<URI_attempt *> to_process)
{
  assert(calling thread has lock on currently_processing);
  assert(calling thread has lock on to_process);

  for each URI_attempt * uri_attemptp in to_process
  {
    if (ready_for_next_attempt(uri_attemptp) &&
      !conflicts_with_currently_processing(currently_processing, uri_attemptp->uri))
    {
      return uri_attemptp;
    }
  }

  return NULL;
}

/** @return the next URI_attempt to try, or NULL if the caller should stop processing URIs */
URI_attempt * next_uri(ThreadSafeSet *currently_processing, some_container<URI_attempt *> to_process)
{
  lock(currently_processing);
  lock(to_process);

  while (to_process is not empty || there's no special flag on to_process that indicates we should stop)
  {
    URI_attempt *uri_attemptp = NULL;
    if ((uri_attemptp = choose_next_uri(currently_processing, to_process)) != NULL)
    {
      assert(ready_for_next_attempt(uri_attemptp));
      assert(!conflicts_with_currently_processing(currently_processing, uri_attemptp->uri));

      remove uri_attemptp from to_process
      add uri_attemptp->uri to currently_processing

      unlock(to_process);
      unlock(currently_processing);
      return uri_attemptp;
    }

    unlock(to_process);
    unlock(currently_processing);
    wait until there might be a change that gives us something to do
    lock(currently_processing);
    lock(to_process);
  }

  unlock(to_process);
  unlock(currently_processing);

  return NULL;
}

failed_attempt(URI_attempt * uri_attemptp, some_container<URI_attempt *> to_process)
{
  log failed uri_attemptp->uri, try number uri_attemptp->attempt at now

  if (uri_attemptp->attempt < some threshhold)
  {
    uri_attemptp->attempt += 1;
    uri_attemptp->next_attempt = now + some_function(uri_attemptp->attempt);
    lock(to_process);
    if (!to_process->add(uri_attemptp))
    {
      free_URI_attempt(uri_attemptp)
      log error
    }
    unlock(to_process);
  }
  else
  {
    log giving up on uri_attemptp->uri after uri_attemptp->attempt tries at now
    free_URI_attempt(uri_attemptp);
  }
}

listen_thread(void *to_process_voidp)
{
  some_container<URI_attempt *> to_process = (some_container<URI_attempt *>)to_process_voidp;

  ...
  {
    ...
    URI uri = something_from_input()
    URI_attempt uri_attemptp = new_URI_attempt(&uri);
    if (!to_process->add(uri_attemptp))
    {
      free_URI_attempt(uri_attemptp)
      log error
    }
  }

  set special flag on to_process that indicates we should stop (may need lock())
}

rsync_thread(void *to_process_voidp, void *currently_processing_voidp)
{
  some_container<URI_attempt *> to_process = (some_container<URI_attempt *>)to_process_voidp;
  ThreadSafeSet *currently_processing = (ThreadSafeSet *)currently_processing_voidp;

  thread_state *statep = new_thread_state();
  URI_attempt *uri_attemptp;

  while ((uri_attemptp = next_uri(currently_processing, to_process)) != NULL)
  {
    copy uri_attemptp->uri to statep->rsync_uri

    log attempting uri_attemptp->uri, try number uri_attemptp->attempt at now

    if (update_directory(statep))
    {
      log succeeded uri_attemptp->uri, try number uri_attemptp->attempt at now

      free_URI_attempt(uri_attemptp);
      uri_attemptp = NULL;

      lock(currently_processing);
      remove_from_set(currently_processing, statep->rsync_uri);
      unlock(currently_processing);
    }
    else
    {
      failed_attempt(uri_attemptp, to_process);
    }
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

  some_container<URI_attempt *> to_process = new_...();
  ThreadSafeSet *currently_processing = new_set();

  thread listener = start_thread(listen_thread, (void*)to_process);
  thread rsyncs[num_threads];
  for (int i = 0; i < num_threads; ++i)
  {
    rsyncs[i] = start_thread(rsync_thread, (void*)to_process, (void*)currently_processing);
  }

  listener.join();
  for (int i = 0; i < num_threads; ++i)
  {
    rsyncs[i].join();
  }
}
