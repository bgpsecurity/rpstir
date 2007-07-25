/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#ifdef __NetBSD__
#include <netinet/in.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana, Mark Reynolds
 *
 * ***** END LICENSE BLOCK ***** */

static char *tdir = NULL;   // top level dir of the repository
static int   tdirlen = 0;   // length of tdir

/*
 * save state in case operations leave db in bad state
 */
static int saveState (scmcon *conp, scm *scmp)
{
  int   i;
  int   sta = 0;
  int   leen;
  char  *name, *stmt;

  for (i = 0; sta == 0 && i < scmp->ntables; i++) {
    name = scmp->tables[i].tabname;
    leen = 2*strlen(name) + 64;
    stmt = (char *)calloc(leen, sizeof(char));
    if ( stmt == NULL )
      return(ERR_SCM_NOMEM);
    snprintf (stmt, leen, "select * from %s into outfile 'backup_%s';", name, name);
    sta = statementscm (conp, stmt);
    free((void *)stmt);
    stmt = NULL;
    if (sta != 0)
      fprintf(stderr, "Could not back up table %s to file backup_%s", name, name);
  }
  return sta;
}

/*
 * restore state when operations leave db in bad state
 */
static int restoreState (scmcon *conp, scm *scmp)
{
  int   i;
  int   sta = 0;
  int   leen;
  char  *name, *stmt;

  for (i = 0; sta == 0 && i < scmp->ntables; i++) {
    name = scmp->tables[i].tabname;
    leen = 2*strlen(name) + 64;
    stmt = (char *)calloc(leen, sizeof(char));
    if ( stmt == NULL )
      return(ERR_SCM_NOMEM);
    snprintf (stmt, leen, "delete from %s;", name);
    sta = statementscm (conp, stmt);
    snprintf (stmt, leen, "load data infile 'backup_%s' into table %s;", name, name);
    free((void *)stmt);
    stmt = NULL;
    sta = statementscm (conp, stmt);
    if (sta != 0)
      fprintf(stderr, "Could not restore to table %s from file backup_%s", name, name);
  }
  return sta;
}

/*
  Perform the delete operation. Return 0 on success and a negative
  error code on failure.
*/

static int deleteop(scmcon *conp, scm *scmp)
{
  int sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in deleteop()\n");
      return(-1);
    }
// drop the database, destroying all tables in the process
  sta = deletedbscm(conp, scmp->db);
  if ( sta == 0 )
    (void)printf("Delete operation succeeded\n");
  else
    (void)fprintf(stderr, "Delete operation failed: %s\n",
		  geterrorscm(conp));
  return(sta);
}

/*
  Perform the create operation. Return 0 on success and a negative
  error code on failure.
*/

static int createop(scmcon *conp, scm *scmp)
{
  int sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in createop()\n");
      return(-1);
    }
// step 1: create the database itself
  sta = createdbscm(conp, scmp->db, scmp->dbuser);
  if ( sta == 0 )
    (void)printf("Create database operation succeeded\n");
  else
    {
      (void)fprintf(stderr, "Create database operation failed: %s\n",
		    geterrorscm(conp));
      return(sta);
    }
// step 2: create all the tables in the database
  sta = createalltablesscm(conp, scmp);
  if ( sta == 0 )
    (void)printf("Create tables operation succeeded\n");
  else
    (void)fprintf(stderr, "Create table %s failed: %s\n",
		  gettablescm(conp), geterrorscm(conp));
  return(sta);
}

static int create2op(scm *scmp, scmcon *conp, char *topdir)
{
  scmkva  aone;
  scmkv   one;
  scmtab *mtab;
  int     sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in create2op()\n");
      return(-1);
    }
  if ( topdir == NULL || topdir[0] == 0 )
    {
      (void)fprintf(stderr, "Must specify a top level repository directory\n");
      return(-2);
    }
// step 1: locate the metadata table
  mtab = findtablescm(scmp, "METADATA");
  if ( mtab == NULL )
    {
      (void)fprintf(stderr, "Cannot find METADATA table\n");
      return(-3);
    }
// step 2: translate "topdir" into an absolute path
  tdir = r2adir(topdir);
  if ( tdir == NULL )
    {
      (void)fprintf(stderr, "Invalid directory: %s\n", topdir);
      return(-4);
    }
// step 3: init the metadata table
  one.column = "rootdir";
  one.value = tdir;
  aone.vec = &one;
  aone.ntot = 1;
  aone.nused = 1;
  sta = insertscm(conp, mtab, &aone);
  if ( sta == 0 )
    (void)printf("Init metadata table succeeded\n");
  else
    (void)fprintf(stderr, "Init metadata table failed: %s\n",
		  geterrorscm(conp));
  return(sta);
}

/*
  Safely print a message to stderr that we are out of memory.
  Cannot use (f)printf since it can try to allocate memory.
*/

static void membail(void)
{
  static char oom[] = "Out of memory!\n";

  (void)write(fileno(stderr), oom, strlen(oom));
}

/*
  Print a usage message.
*/

static void usage(void)
{
  (void)printf("Usage:\n");
  (void)printf("\t-t topdir\tcreate all database tables\n");
  (void)printf("\t-x\tdestroy all database tables\n");
  (void)printf("\t-y\tforce operation: do not ask for confirmation\n");
  (void)printf("\t-d dir\tdelete the indicated file\n");
  (void)printf("\t-f file\tadd the indicated file\n");
  (void)printf("\t-F file\tadd the indicated trusted file\n");
  (void)printf("\t-w port\tstart an rsync listener on port\n");
  (void)printf("\t-p\trun the socket listen in perpetual mode\n");
  (void)printf("\t-h\tdisplay usage and exit\n");
}

/*
  Ask a yes or no question. Returns 1 for yes, 0 for no, -1 for error.
*/

static int yorn(char *q)
{
  char ans[8];

  if ( q == NULL || q[0] == 0 )
    return(-1);
  (void)printf("%s? ", q);
  memset(ans, 0, 8);
  if ( fgets(ans, 8, stdin) == NULL || ans[0] == 0 ||
       toupper((int)(ans[0])) != 'Y' )
    return(0);
  else
    return(1);
}

/*
  The port name has one of the forms tN or uN or N, indicating
  tcp port N, udp port N, or just plain (tcp) port N.
*/

static int makesock(char *porto, int *protosp)
{
  struct sockaddr_in sinn;
  struct sockaddr_in sout;
  struct hostent    *hen;
  socklen_t leen;
  char hn[256];
  char tu = 't';
  int  protos;
  int  sta;
  int  port;
  int  offs = 0;
//  int  one = 1;
  int  s;

  if ( porto[0] == 'u' || porto[0] == 'U' )
    tu = 'u', offs = 1;
  else if ( porto[0] == 't' || porto[0] == 'T' )
    tu = 't', offs = 1;
  port = atoi(porto+offs);
  if ( port <= 0 )
    return(-1);
  protos = *protosp;
  if ( protos < 0 )
    {
      protos = socket(AF_INET, SOCK_STREAM, 0);
      if ( protos < 0 )
	return(protos);
      hn[0] = 0;
      sta = gethostname(hn, 256);
      if ( sta < 0 )
	{
	  close(protos);
	  return(sta);
	}
      hen = gethostbyname(hn);
      if ( hen == NULL )
	{
          (void)fprintf(stderr, "Cannot lookup hostname %s\n", hn);
	  close(protos);
	  return(-1);
	}
      memset(&sinn, 0, sizeof(sinn));
      memcpy(&sinn.sin_addr.s_addr, hen->h_addr_list[0],
	     hen->h_length);
      sinn.sin_family = AF_INET;
      sinn.sin_port = htons(port);
      sta = bind(protos, (struct sockaddr *)&sinn, sizeof(sinn));
      if ( sta < 0 )
	{
	  close(protos);
	  return(sta);
	}
//  (void)setsockopt(protos, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
      sta = listen(protos, 1);
      if ( sta < 0 )
	{
	  close(protos);
	  return(sta);
	}
      *protosp = protos;
    }
  leen = sizeof(sout);
  s = accept(protos, (struct sockaddr *)&sout, &leen);
//  (void)close(protos);
  return(s);
}

static char *afterwhite(char *ptr)
{
  char *run = ptr;
  char  c;

  while ( 1 )
    {
      c = *run;
      if ( c == 0 )
	break;
      if ( ! isspace((int)c) )
	break;
      run++;
    }
  return(run);
}

static char *hdir = NULL;

static int aur(scm *scmp, scmcon *conp, char what, char *valu)
{
  char *outdir;
  char *outfile;
  char *outfull;
  int   sta, trusted;

  sta = splitdf(hdir, NULL, valu, &outdir, &outfile, &outfull);
  if (sta != 0) {
    fprintf(stderr, "Error loading file %s/%s: %s\n", hdir, valu, err2string(sta));
    return sta;
  }
  trusted = strstr(outdir, "TRUST") != NULL;
  if ( sta < 0 )
    return(sta);
  switch ( what )
    {
    case 'a':
      sta = add_object(scmp, conp, outfile, outdir, outfull, trusted);
      break;
    case 'r':
      sta = delete_object(scmp, conp, outfile, outdir, outfull);
      break;
    case 'u':
      (void)delete_object(scmp, conp, outfile, outdir, outfull);
      sta = add_object(scmp, conp, outfile, outdir, outfull, trusted);
      break;
    default:
      break;
    }
  free((void *)outdir);
  free((void *)outfile);
  free((void *)outfull);
  return(sta);
}

static char *hasoneline(char *inp, char **nextp)
{
  char *crlf;
  int   leen;
  int   crleen;

  *nextp = NULL;
  if ( inp == NULL )
    return(NULL);
  leen = strlen(inp);
  crlf = strstr(inp, "\r\n");
  if ( crlf == NULL )
    return(NULL);
  *crlf++ = 0;
  *crlf++ = 0;
  if ( (int)(crlf-inp) < leen ) {
    crleen = strlen(crlf);
    *nextp = calloc (crleen + 1, sizeof(char));
    strncpy (*nextp, crlf, crleen);
  }
  return(inp);
}

/*
  This function processes socket data line by line. First, it looks
  in "left" to see if this contains one or more lines. In such a
  case it returns a pointer to the first such line, and modifies left
  so that that line is deleted. If left does not contain a complete
  line this function will read as much socket data as it can. It will
  stuff the first complete line (if any) into the return code, and
  put the remaining stuff into left.
*/

static char *sock1line(int s, char **leftp)
{
  char *left2;
  char *left = *leftp;
  char *next = NULL;
  char *ptr;
  int   leen = 0;
  int   rd = 0;
  int   sta;

  ptr = hasoneline(left, &next);
  if ( ptr != NULL )  // left had at least one line
    {
      *leftp = next;
      return(ptr);
    }
  if ( left != NULL )
    leen = strlen(left);
  sta = ioctl(s, FIONREAD, &rd);
  if ( sta < 0 || rd <= 0 )
    return(NULL);
  left2 = (char *)calloc(leen+rd+1, sizeof(char));
  if ( left2 == NULL )
    return(NULL);
  (void)strncpy(left2, left, leen);
  sta = recv(s, left2+leen, rd, 0);
  if ( sta < 0 )
    sta = 0;
  left2[leen+sta] = 0;
  //  free((void *)left);
  left = left2;
  ptr = hasoneline(left, &next);
  if ( ptr != NULL )
    {
      *leftp = next;
      return(ptr);
    }
  *leftp = left;
  return(NULL);
}

/*
  Determine if the peer of a socket has disconnected. This function
  returns 0 if the other end appears to still be connected, and a
  negative error code otherwise.
*/

static int probe(int s)
{
  struct sockaddr_in from;
  unsigned int  fromlen = sizeof(from);
//  char one;
//  int  serrno;
  int  rd;
  int  e;

  if ( s < 0 )
    return(-1);
// test 1: zero byte write
//  e = send(s, NULL, 0, 0);  // test 1 hangs synchronization
//  if ( e < 0 )
//    return(-2);
// test 2: getpeername
  memset(&from, 0, fromlen);
  e = getpeername(s, (struct sockaddr *)&from, &fromlen);
  if ( e < 0 )
    return(-3);
// test 3: peek
//  errno = 0;  // test 3 hangs synchronization
//  e = recv(s, &one, 1, MSG_PEEK);
//  serrno = errno;
  //  if ( e == 0 )
  //  return(-4);
//  if ( e < 0 && serrno == ECONNRESET )
//    return(-5);
// test 4: socket ioctl
  e = ioctl(s, FIONREAD, &rd);
  if ( e < 0 || rd < 0 )
    return(-6);
  return(0);
}

/*
  Receive one or more lines of data over the socket and process
  them.  The lines received will look like TAG whitespace VALUE CRLF.
  The following tags are defined:


   B (begin).  This is sent when the AUR program starts. Its VALUE is the
               current date and time.

   E (end).  Sent when the AUR program is done. VALUE is the current date and
             time.  AUR may close its end of the socket immediately after
             sending this message; it need not wait.

   C (cd): Sent when the current directory is read or changed.

   A (add). Sent when a file is added to the repository. VALUE is the full,
            absolute path to the file.

   U (update). Sent when a file is updated in the repository, e.g. the
               contents change but the filename remains the same and is in the
               same directory.

   R (remove). Sent when a file is removed from the repository.  VALUE is the
               full path to the file.

   L (link). Sent when a link (hard or symbolic) is made between two files in
             the repository. VALUE is formed as follows:
                "filename1" SP filename2.
             Filename1 is a full pathname in double quotes; it is followed by
             a single space, and then filename2 which is also a full pathname.
             The link direction is filename1 -> filename2.

   F (fatal error). Sent (if possible) when the AUR program detects an
                    unrecoverable error occurs. VALUE is the error text. It
                    is expected that AUR will immediately close its end of the
                    socket when this happens (perhaps even without being able
                    to send an E message).

   X (error). Sent when an error occurs. VALUE is error text.  This is an
              optional message.

   W (warning). Sent when a warning occurs. VALUE is warning text. Optional
                message.

   S (save state). Sent when it makes sense to save the state

   V (restore state). Sent when it makes sense to restore the state

   I (information). Sent to convey arbitrary information.  VALUE is the
                    informational text. Optional message.
*/

static int sockline(scm *scmp, scmcon *conp, FILE *logfile, int s)
{
  char *left = NULL;
  char *ptr;
  char *valu;
  char  c;
  int   done = 0;
  int   sta = 0;

  while ( 1 )
    {
      if ( (sta=probe(s)) < 0 )
	{
	  (void)fprintf(stderr, "Probe error %d\n", sta);
	  (void)fprintf(logfile, "Probe error %d\n", sta);
	  return(sta);
	}
      ptr = sock1line(s, &left);
      if ( ptr == NULL )
	continue;
      (void)printf("Sockline: %s\n", ptr);
      (void)fprintf(logfile, "Sockline: %s\n", ptr);
      c = ptr[0];
      if ( !isspace((int)(ptr[1])) )
	{
	  (void)fprintf(stderr, "Invalid line: ignored\n");
	  free((void *)ptr);
	  continue;
	}
      valu = afterwhite(ptr+1);
      switch ( c )
	{
	case 'b':		/* begin */
	case 'B':
	  (void)fprintf(logfile, "AUR beginning at %s\n", valu);
	  break;
	case 'e':
	case 'E':		/* end */
	  (void)fprintf(logfile, "AUR ending at %s\n", valu);
	  done = 1;
	  break;
	case 'c':
	case 'C':		/* cd */
	  if ( hdir != NULL )
	    {
	      free((void *)hdir);
	      hdir = NULL;
	    }
	  hdir = strdup(valu);
	  break;
	case 'a':
	case 'A':		/* add */
	  (void)fprintf(logfile, "AUR add request: %s\n", valu);
	  sta = aur(scmp, conp, 'a', valu);
	  (void)fprintf(logfile, "Status was %d", sta);
	  if ( sta < 0 )
	    (void)fprintf(logfile, " (%s)", err2string(sta));
	  (void)fprintf(logfile, "\n");
	  break;
	case 'u':
	case 'U':		/* update */
	  (void)fprintf(logfile, "AUR update request: %s\n", valu);
	  sta = aur(scmp, conp, 'u', valu);
	  (void)fprintf(logfile, "Status was %d", sta);
	  if ( sta < 0 )
	    (void)fprintf(logfile, " (%s)", err2string(sta));
	  (void)fprintf(logfile, "\n");
	  break;
	case 'r':
	case 'R':		/* remove */
	  (void)fprintf(logfile, "AUR remove request: %s\n", valu);
	  sta = aur(scmp, conp, 'r', valu);
	  (void)fprintf(logfile, "Status was %d", sta);
	  if ( sta < 0 )
	    (void)fprintf(logfile, " (%s)", err2string(sta));
	  (void)fprintf(logfile, "\n");
	  break;
	case 'l':
	case 'L':		/* link */
	  (void)fprintf(logfile, "AUR link request: %s\n", valu);
	  break;
	case 'f':
	case 'F':		/* fatal error */
	  (void)fprintf(logfile, "AUR fatal error: %s\n", valu);
	  done = 1;
	  break;
	case 'x':
	case 'X':		/* error */
	  (void)fprintf(logfile, "AUR error: %s\n", valu);
	  break;
	case 'w':
	case 'W':		/* warning */
	  (void)fprintf(logfile, "AUR warning: %s\n", valu);
	  break;
	case 'i':
	case 'I':		/* information */
	  (void)fprintf(logfile, "AUR message: %s\n", valu);
	  break;
	case 's':
	case 'S':		/* save */
	  (void)saveState(conp, scmp);
	  break;
	case 'v':
	case 'V':		/* restore */
	  (void)restoreState(conp, scmp);
	  break;
	case 'y':
	case 'Y':		/* synchronize */
	  (void)write(s, "Y", 1);
	  break;
	case 0:
	  break;
	default:
	  (void)fprintf(logfile, "AUR invalid tag '%c' ignored\n", c);
	  break;
	}
      free((void *)ptr);
      if ( done == 1 )
	break;
    }
  return(sta);
}

// putative command line args:
//   -t topdir           create all tables, set rep root to "topdir"
//   -x                  destroy all tables
//   -y                  force operation, don't ask
//   -h                  print help
//   -d object           delete the given object
//   -f file             add the given object
//   -F file             add the given trusted object
//   -w port             operate in wrapper mode using the given socket port
//   -p                  with -w indicates to run perpetually, e.g. as a daemon

int main(int argc, char **argv)
{
  scmcon *testconp = NULL;
  scmcon *realconp = NULL;
  scm    *scmp = NULL;
  FILE   *logfile = NULL;
  char   *thedelfile = NULL;
  char   *topdir = NULL;
  char   *thefile = NULL;
  char   *outfile = NULL;
  char   *outfull = NULL;
  char   *outdir = NULL;
  char   *tmpdsn = NULL;
  char   *password = NULL;
  char   *ne;
  char   *porto = NULL;
  char    errmsg[1024];
  time_t  nw;
  int ians = 0;
  int do_create = 0;
  int do_delete = 0;
  int do_sockopts = 0;
  int perpetual = 0;
  int really = 0;
  int trusted = 0;
  int force = 0;
  int sta = 0;
  int s;
  int c;

  (void)setbuf(stdout, NULL);
  if ( argc <= 1 )
    {
      usage();
      return(1);
    }
  while ( (c = getopt(argc, argv, "t:xyhd:f:F:w:p")) != EOF )
    {
      switch ( c )
	{
	case 't':
	  do_create++;
	  topdir = optarg;
	  break;
	case 'x':
	  do_delete++;
	  break;
	case 'y':
	  force++;
	  break;
	case 'D':
	  trusted++;
	case 'd':
	  thedelfile = optarg;
	  break;
	case 'F':
	  trusted++;
	case 'f':
	  thefile = optarg;
	  break;
	case 'w':
	  do_sockopts++;
	  porto = optarg;
	  break;
	case 'p':
	  perpetual++;
	  break;
	case 'h':
	  usage();
	  return(0);
	default:
	  (void)fprintf(stderr, "Invalid option '%c'\n", c);
	  usage();
	  return(1);
	}
    }
  if ( force == 0 )
    {
      if ( do_delete > 0 )
	{
	  ians = yorn("Do you REALLY want to delete all database tables");
	  if ( ians <= 0 )
	    {
	      (void)printf("Delete operation cancelled\n");
	      return(1);
	    }
	  really++;
	}
      if ( (do_create > 0) && (really == 0) )
	{
	  ians = yorn("Do you REALLY want to create all database tables");
	  if ( ians <= 0 )
	    {
	      (void)printf("Create operation cancelled\n");
	      return(1);
	    }
	  really++;
	}
    }
  scmp = initscm();
  if ( scmp == NULL )
    {
      (void)fprintf(stderr,
		    "Internal error: cannot initialize database schema\n");
      return(-2);
    }
/*
  If a create or delete operation is being performed, then a test dsn
  will be needed; create it now and defer the creation of the
  real dsn until later. Otherwise, create the real dsn.

  A test dsn is needed for operations that operate on the overall
  database state as opposed to the apki tables, namely the create and
  delete operations.

  Note that this code is done here in main() rather than in a subroutine
  in order to avoid passing parameter(s) on the stack that contain the
  root database password.
*/
  if ( (do_create+do_delete) > 0 )
    {
/*
  These privileged operations will need a password.
*/
      password = getpass("Enter MySQL root password: ");
      tmpdsn = makedsnscm(scmp->dsnpref, "test", "root", password);
      if ( password != NULL )
	memset(password, 0, strlen(password));
      if ( tmpdsn == NULL )
	{
	  membail();
	  return(-1);
	}
      testconp = connectscm(tmpdsn, errmsg, 1024);
      memset(tmpdsn, 0, strlen(tmpdsn));
      free((void *)tmpdsn);
      if ( testconp == NULL )
	{
	  (void)fprintf(stderr, "Cannot connect to DSN: %s\n",
			errmsg);
	  freescm(scmp);
	  return(-1);
	}
    }
  else
    {
      realconp = connectscm(scmp->dsn, errmsg, 1024);
      if ( realconp == NULL )
	{
	  (void)fprintf(stderr, "Cannot connect to DSN %s: %s\n",
			scmp->dsn, errmsg);
	  freescm(scmp);
	  return(-1);
	}
    }
/*
  Process command line options in the following order: delete, create, dofile,
  dodir, listener.
*/
  if ( do_delete > 0 )
    sta = deleteop(testconp, scmp);
  if ( do_create > 0 && sta == 0 )		/* first phase of create */
    sta = createop(testconp, scmp);
/*
  Don't need the test connection any more
*/
  if ( testconp != NULL )
    {
      disconnectscm(testconp);
      testconp = NULL;
    }
/*
  If there has been an error, bail out.
*/
  if ( sta < 0 )
    {
      if ( realconp != NULL )
	disconnectscm(realconp);
      freescm(scmp);
      if ( tdir != NULL )
	free((void *)tdir);
      return(sta);
    }
/*
  If a connection to the real DSN has not been opened yet, open it now.
*/
  if ( realconp == NULL )
    {
      realconp = connectscm(scmp->dsn, errmsg, 1024);
      if ( realconp == NULL )
	{
	  if ( do_delete == 0 )
	    (void)fprintf(stderr, "Cannot connect to DSN %s: %s\n",
			  scmp->dsn, errmsg);
	  freescm(scmp);
	  if ( tdir != NULL )
	    free((void *)tdir);
	  return(-1);
	}
    }
/*
  If a create operation was requested, complete it now.
*/
  if ( do_create > 0 && sta == 0 )
    sta = create2op(scmp, realconp, topdir);
/*
  If the top level repository directory is not set, then retrieve it from
  the database.
*/
  if ( tdir == NULL && sta == 0 )
    {
      tdir = retrieve_tdir(scmp, realconp, &sta);
      if ( tdir == NULL )
	(void)fprintf(stderr,
		      "Cannot retrieve top level repository info from DB\n");
    }
  if ( sta == 0 )
    {
      (void)printf("Top level repository directory is %s\n", tdir);
      tdirlen = strlen(tdir);
    }
/*
  Setup for actual SSL operations
*/
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
/*
  Open the logfile in preparation for actual DB operations.
*/
  logfile = fopen("rcli.log", "a+");
  if ( logfile == NULL )
    {
      (void)fprintf(stderr, "Cannot create logfile\n");
      return(-1);
    }
  time(&nw);
  (void)setbuf(logfile, NULL);
  (void)fprintf(logfile, "Rsync client session start: %s", ctime(&nw));
  if ( thefile != NULL && sta == 0 )
    {
// Check that the file is in the repository, ask if not and force is off
      sta = splitdf(NULL, NULL, thefile, &outdir, &outfile, &outfull);
      if ( sta == 0 )
	{
	  if ( strncmp(tdir, outdir, tdirlen) != 0 && force == 0 )
	    {
	      ians =
		yorn("That file is not in the repository. Proceed anyway");
	      if ( ians <= 0 )
		sta = 1;
	    }
	  if ( strstr(outdir, "TRUST") != NULL )
	    trusted++;
// if the user has declared it to be trusted, or if it is in a TRUSTed
// directory ask for verification unless force is set
	  if ( trusted > 0 && force == 0 && sta == 0 )
	    {
	      ians = yorn("Really declare this file as trusted");
	      if ( ians <= 0 )
		sta = 1;
	    }
	  if ( sta == 1 )
	    (void)printf("File operation cancelled\n");
	  if ( sta == 0 )
	    {
	      (void)fprintf(logfile, "Attempting to add file %s\n", outfile);
	      sta = add_object(scmp, realconp, outfile, outdir, outfull,
			       trusted);
	      if ( sta < 0 )
		{
		  (void)fprintf(stderr,
				"Could not add file %s: error %s (%d)\n",
				thefile, err2string(sta), sta);
		  (void)fprintf(logfile,
				"Could not add file %s: error %s (%d)\n",
				thefile, err2string(sta), sta);
		  if ( sta == ERR_SCM_SQL )
		    {
		      ne = geterrorscm(realconp);
		      if ( ne != NULL && ne != 0 )
			(void)fprintf(logfile, "\t%s\n", ne);
		    }
		}
	      else
		(void)fprintf(logfile, "Add operation succeeded\n");
	    }
	  free((void *)outdir);
	  free((void *)outfile);
	  free((void *)outfull);
	}
      else
	(void)fprintf(stderr, "Error: %s (%d)\n", err2string(sta), sta);
    }
  if ( thedelfile != NULL && sta == 0 )
    {
      sta = splitdf(NULL, NULL, thedelfile, &outdir, &outfile, &outfull);
      if ( sta == 0 )
	{
	  sta = delete_object(scmp, realconp, outfile, outdir, outfull);
	  if ( sta < 0 )
	    {
	      (void)fprintf(stderr,
			    "Could not delete file %s: error %s (%d)\n",
			    thefile, err2string(sta), sta);
	      (void)fprintf(logfile,
			    "Could not delete file %s: error %s (%d)\n",
			    thefile, err2string(sta), sta);
	      if ( sta == ERR_SCM_SQL )
		{
		  ne = geterrorscm(realconp);
		  if ( ne != NULL && ne != 0 )
		    (void)fprintf(logfile, "\t%s\n", ne);
		}
	    }
	  else
	    (void)fprintf(logfile, "Delete operation succeeded\n");
	  free((void *)outdir);
	  free((void *)outfile);
	  free((void *)outfull);
	}
      else
	(void)fprintf(stderr, "Error: %s (%d)\n", err2string(sta), sta);
    }
  if ( do_sockopts > 0 && porto != NULL && sta == 0 )
    {
      int protos = (-1);
      do
	{
	  (void)printf("Creating a socket on port %s\n", porto);
	  s = makesock(porto, &protos);
	  if ( s < 0 )
	    (void)fprintf(stderr, "Could not create socket\n");
	  else
	    {
	      sta = sockline(scmp, realconp, logfile, s);
	      (void)printf("Socket connection closed\n");
	      (void)close(s);
	    }
	} while ( perpetual > 0 ) ;
      if ( protos >= 0 )
	(void)close(protos);
    }
  (void)ranlast(scmp, realconp, "RSYNC");
  if ( realconp != NULL )
    disconnectscm(realconp);
  freescm(scmp);
  if ( tdir != NULL )
    free((void *)tdir);
  time(&nw);
  (void)fprintf(logfile, "Rsync client session end %s", ctime(&nw));
  (void)fclose(logfile);
  return(sta);
}
