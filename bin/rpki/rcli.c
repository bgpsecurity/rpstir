/*
 * $Id$ 
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
#include <inttypes.h>
#ifdef __NetBSD__
#include <netinet/in.h>
#endif
#ifdef __OpenBSD__
#include <netinet/in.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "rpki/scm.h"
#include "rpki/scmf.h"
#include "rpki/sqhl.h"
#include "rpki/diru.h"
#include "rpki/myssl.h"
#include "rpki/cms/roa_utils.h"
#include "rpki/err.h"
#include "config/config.h"
#include "util/logging.h"


static char *tdir = NULL;       // top level dir of the repository
static int tdirlen = 0;         // length of tdir

/*
 * save state in case operations leave db in bad state
 */
static int saveState(
    scmcon * conp,
    scm * scmp)
{
    int i;
    int sta = 0;
    int leen;
    char *name,
       *stmt;

    for (i = 0; sta == 0 && i < scmp->ntables; i++)
    {
        name = scmp->tables[i].tabname;
        leen = 2 * strlen(name) + 64;
        stmt = (char *)calloc(leen, sizeof(char));
        if (stmt == NULL)
            return (ERR_SCM_NOMEM);
        snprintf(stmt, leen, "select * from %s into outfile 'backup_%s';",
                 name, name);
        sta = statementscm_no_data(conp, stmt);
        free((void *)stmt);
        stmt = NULL;
        if (sta != 0)
            LOG(LOG_ERR, "Could not back up table %s to file backup_%s",
                    name, name);
    }
    return sta;
}

/*
 * restore state when operations leave db in bad state
 */
static int restoreState(
    scmcon * conp,
    scm * scmp)
{
    int i;
    int sta = 0;
    int leen;
    char *name,
       *stmt;

    for (i = 0; sta == 0 && i < scmp->ntables; i++)
    {
        name = scmp->tables[i].tabname;
        leen = 2 * strlen(name) + 64;
        stmt = (char *)calloc(leen, sizeof(char));
        if (stmt == NULL)
            return (ERR_SCM_NOMEM);
        snprintf(stmt, leen, "delete from %s;", name);
        sta = statementscm_no_data(conp, stmt);
        snprintf(stmt, leen, "load data infile 'backup_%s' into table %s;",
                 name, name);
        free((void *)stmt);
        stmt = NULL;
        sta = statementscm_no_data(conp, stmt);
        if (sta != 0)
            LOG(LOG_ERR,
                    "Could not restore to table %s from file backup_%s", name,
                    name);
    }
    return sta;
}

/*
 * Perform the delete operation. Return 0 on success and a negative error code 
 * on failure. 
 */

static int deleteop(
    scmcon * conp,
    scm * scmp)
{
    int sta;

    if (conp == NULL || scmp == NULL || scmp->db == NULL || scmp->db[0] == 0)
    {
        LOG(LOG_ERR, "Internal error in deleteop()");
        return (-1);
    }
    // drop the database, destroying all tables in the process
    sta = deletedbscm(conp, scmp->db);
    if (sta == 0)
        LOG(LOG_NOTICE, "Delete database (%s) operation succeeded",
            scmp->db);
    else
        LOG(LOG_ERR, "Delete database (%s) operation failed: %s",
            scmp->db, geterrorscm(conp));
    return (sta);
}

/*
 * Perform the create operation. Return 0 on success and a negative error code 
 * on failure. 
 */

static int createop(
    scmcon * conp,
    scm * scmp)
{
    int sta;

    if (conp == NULL || scmp == NULL || scmp->db == NULL || scmp->db[0] == 0)
    {
        LOG(LOG_ERR, "Internal error in createop()");
        return (-1);
    }
    // step 1: create the database itself
    sta = createdbscm(conp, scmp->db, scmp->dbuser);
    if (sta == 0)
        LOG(LOG_NOTICE, "Create database (%s) operation succeeded",
            scmp->db);
    else
    {
        LOG(LOG_ERR, "Create database (%s) operation failed: %s",
            scmp->db, geterrorscm(conp));
        return (sta);
    }
    // step 2: create all the tables in the database
    sta = createalltablesscm(conp, scmp);
    if (sta == 0)
        LOG(LOG_NOTICE, "Create tables operation succeeded");
    else
        LOG(LOG_ERR, "Create table %s failed: %s",
                gettablescm(conp), geterrorscm(conp));
    return (sta);
}

static int create2op(
    scm * scmp,
    scmcon * conp,
    char *topdir)
{
    scmkva aone;
    scmkv one;
    scmtab *mtab;
    int sta;

    if (conp == NULL || scmp == NULL || scmp->db == NULL || scmp->db[0] == 0)
    {
        LOG(LOG_ERR, "Internal error in create2op()");
        return (-1);
    }
    if (topdir == NULL || topdir[0] == 0)
    {
        LOG(LOG_ERR, "Must specify a top level repository directory");
        return (-2);
    }
    // step 1: locate the metadata table
    mtab = findtablescm(scmp, "METADATA");
    if (mtab == NULL)
    {
        LOG(LOG_ERR, "Cannot find METADATA table");
        return (-3);
    }
    // step 2: translate "topdir" into an absolute path
    tdir = r2adir(topdir);
    if (tdir == NULL)
    {
        LOG(LOG_ERR, "Invalid directory: %s", topdir);
        return (-4);
    }
    // step 3: init the metadata table
    one.column = "rootdir";
    one.value = tdir;
    aone.vec = &one;
    aone.ntot = 1;
    aone.nused = 1;
    aone.vald = 0;
    sta = insertscm(conp, mtab, &aone);
    if (sta == 0)
        LOG(LOG_NOTICE, "Init metadata table succeeded");
    else
        LOG(LOG_ERR, "Init metadata table failed: %s", geterrorscm(conp));
    return (sta);
}

/*
 * Safely print a message to stderr that we are out of memory. Cannot use
 * (f)printf since it can try to allocate memory. 
 */

static void membail(
    void)
{
    static char oom[] = "Out of memory!\n";

    (void)write(fileno(stderr), oom, strlen(oom));
}

/*
 * Print a usage message. 
 */

static void usage(
    void)
{
    (void)printf("Usage:\n");
    (void)
        printf
        ("  -d dir     delete the indicated file (using full pathname)\n");
    (void)printf("  -f file    add the indicated file\n");
    (void)printf("  -F file    add the indicated trusted file\n");
    (void)printf("  -p         run the socket listener in perpetual mode\n");
    (void)printf("  -t topdir  create all database tables\n");
    (void)printf("  -w port    start an rsync listener on port\n");
    (void)printf("  -x         destroy all database tables\n");
    (void)printf("             Note that if you use -x without -t,\n");
    (void)printf("             no other operations can succeed.\n");
    (void)
        printf("  -y         force operation: do not ask for confirmation\n");
    (void)printf("  -a         allow expired certificates\n");
    (void)printf("  -s         do stricter profile checks\n");
    (void)printf("  -h         display usage and exit\n");
}

/*
 * Ask a yes or no question. Returns 1 for yes, 0 for no, -1 for error. 
 */

static int yorn(
    char *q)
{
    char ans[8];

    if (q == NULL || q[0] == 0)
        return (-1);
    (void)printf("%s? ", q);
    memset(ans, 0, 8);
    if (fgets(ans, 8, stdin) == NULL || ans[0] == 0 ||
        toupper((int)(ans[0])) != 'Y')
        return (0);
    else
        return (1);
}

static int makesock(
    uint16_t port,
    int *protosp)
{
    struct sockaddr_in sinn;
    struct sockaddr_in sout;
    socklen_t leen;
    int protos;
    int sta;
    static int64_t num_accepted_connections = 0;
    static int64_t num_failed_connections = 0;
    int one = 1;
    int s;

    protos = *protosp;
    if (protos < 0)
    {
        LOG(LOG_INFO, "Creating a socket on port %" PRIu16, port);
        protos = socket(AF_INET, SOCK_STREAM, 0);
        if (protos < 0)
        {
            perror("Failed to create socket");
            return (protos);
        }

        // Enable address reuse, so that TIME_WAIT doesn't prevent restart.
        sta = setsockopt(protos, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (sta < 0)
        {
            LOG(LOG_WARNING, "Failed to set SO_REUSEADDR");
            perror("Failed to set SO_REUSEADDR");
        }

        memset(&sinn, 0, sizeof(sinn));
        sinn.sin_addr.s_addr = htonl(INADDR_ANY);
        sinn.sin_family = AF_INET;
        sinn.sin_port = htons(port);
        sta = bind(protos, (struct sockaddr *)&sinn, sizeof(sinn));
        if (sta < 0)
        {
            perror("Failed to bind to port");
            close(protos);
            return (sta);
        }
        sta = listen(protos, 5);
        if (sta < 0)
        {
            perror("Failed to listen on socket");
            close(protos);
            return (sta);
        }
        *protosp = protos;
    }
    LOG(LOG_INFO, "Waiting for a connection on port %" PRIu16, port);
    leen = sizeof(sout);
    s = accept(protos, (struct sockaddr *)&sout, &leen);
    if (s >= 0)
    {
        num_accepted_connections++;
        LOG(LOG_INFO, "New connection accepted on port %" PRIu16 " (#%" PRId64 ")",
                port, num_accepted_connections);
    }
    else
    {
        num_failed_connections++;
        LOG(LOG_ERR, "Failed to accept connection on port %" PRIu16 " (failure #%"
                PRId64 ")", port, num_failed_connections);
    }
    // (void)close(protos);
    return (s);
}

static char *afterwhite(
    char *ptr)
{
    char *run = ptr;
    char c;

    while (1)
    {
        c = *run;
        if (c == 0)
            break;
        if (!isspace((int)(unsigned char)c))
            break;
        run++;
    }
    return (run);
}

/*******************
static char *splitOnWhite(char *ptr) {
  char *run = ptr;
  while (*run && ! isspace((int)(unsigned char)*run)) run++;
  if (! *run) return run;
  *run = 0;
  run++;
  while (isspace((int)(unsigned char)*run)) run++;
  return run;
}
********************/

static char *hdir = NULL;

static int aur(
    scm * scmp,
    scmcon * conp,
    char what,
    char *valu)
{
    char *outdir;
    char *outfile,
       *outfull;
    int sta,
        trusted = 0;

    sta = splitdf(hdir, NULL, valu, &outdir, &outfile, &outfull);
    if (sta != 0)
    {
        LOG(LOG_ERR, "Error loading file %s/%s: %s", hdir, valu,
                err2string(sta));
        free((void *)outdir);
        free((void *)outfile);
        free((void *)outfull);
        return sta;
    }
    // trusted = strstr(outdir, "TRUST") != NULL;
    if (sta < 0)
        return (sta);
    switch (what)
    {
    case 'a':
        sta = add_object(scmp, conp, outfile, outdir, outfull, trusted);
        break;
    case 'r':
        sta = delete_object(scmp, conp, outfile, outdir, outfull, 0);
        break;
    case 'u':
        (void)delete_object(scmp, conp, outfile, outdir, outfull, 0);
        sta = add_object(scmp, conp, outfile, outdir, outfull, trusted);
        break;
    default:
        break;
    }
    free((void *)outdir);
    free((void *)outfile);
    free((void *)outfull);
    return (sta);
}

static char *hasoneline(
    char *inp,
    char **nextp)
{
    char *crlf;
    int leen;
    int crleen;

    *nextp = NULL;
    if (inp == NULL)
        return (NULL);
    leen = strlen(inp);
    crlf = strstr(inp, "\r\n");
    if (crlf == NULL)
        return (NULL);
    *crlf++ = 0;
    *crlf++ = 0;
    if ((int)(crlf - inp) < leen)
    {
        crleen = strlen(crlf);
        *nextp = calloc(crleen + 1, sizeof(char));
        strncpy(*nextp, crlf, crleen);
    }
    return (inp);
}

/*
 * This function processes socket data line by line. First, it looks in "left" 
 * to see if this contains one or more lines. In such a case it returns a
 * pointer to the first such line, and modifies left so that that line is
 * deleted. If left does not contain a complete line this function will read
 * as much socket data as it can. It will stuff the first complete line (if
 * any) into 'line', and put the remaining stuff into left. 
 */

static int sock1line(
    int s,
    char **leftp,
    char **line)
{
    char *left2;
    char *left = *leftp;
    char *next = NULL;
    char *ptr;
    int leen = 0;
    int rd = 0;
    int sta;

    ptr = hasoneline(left, &next);
    if (ptr != NULL)            // left had at least one line
    {
        *leftp = next;
        *line = ptr;
        return 0;
    }
    if (left != NULL)
        leen = strlen(left);
    sta = ioctl(s, FIONREAD, &rd);
    if (sta < 0)
        return sta;
    /*
     * Blocking mode, by A. Chi, 3/18/11.  Even if no data is available yet,
     * block until we can read at least one byte. 
     */
    if (rd <= 0)
        rd = 1;
    left2 = (char *)calloc(leen + rd + 1, sizeof(char));
    if (left2 == NULL)
    {
        return -1;
    }
    (void)strncpy(left2, left, leen);
    sta = recv(s, left2 + leen, rd, MSG_WAITALL);
    if (sta <= 0)               // 0 indicates orderly connection shutdown
        return -1;
    left2[leen + sta] = 0;
    // free((void *)left);
    left = left2;
    ptr = hasoneline(left, &next);
    if (ptr != NULL)
    {
        free((void *)*leftp);
        *leftp = next;
        *line = ptr;
        return 0;
    }
    free((void *)*leftp);
    *leftp = left;
    *line = NULL;
    return 0;
}

/*
 * Determine if the peer of a socket has disconnected. This function returns 0 
 * if the other end appears to still be connected, and a negative error code
 * otherwise. 
 */
/*
 * Probe routine commented out by A. Chi, on 3/18/11 because if we are in
 * blocking mode, it is unnecessary. 
 */
/*
 * static int probe(int s) { struct sockaddr_in from; unsigned int fromlen =
 * sizeof(from); // char one; // int serrno; int rd; int e;
 * 
 * if ( s < 0 ) return(-1); // test 1: zero byte write // e = send(s, NULL, 0, 
 * 0); // test 1 hangs synchronization // if ( e < 0 ) // return(-2); // test
 * 2: getpeername memset(&from, 0, fromlen); e = getpeername(s, (struct
 * sockaddr *)&from, &fromlen); if ( e < 0 ) return(-3); // test 3: peek //
 * errno = 0; // test 3 hangs synchronization // e = recv(s, &one, 1,
 * MSG_PEEK); // serrno = errno; // if ( e == 0 ) // return(-4); // if ( e < 0 
 * && serrno == ECONNRESET ) // return(-5); // test 4: socket ioctl e =
 * ioctl(s, FIONREAD, &rd); if ( e < 0 || rd < 0 ) return(-6); return(0); } 
 */

/*
 * Receive one or more lines of data over the socket and process them.  The
 * lines received will look like TAG whitespace VALUE CRLF. The following tags 
 * are defined:
 * 
 * 
 * B (begin).  This is sent when the AUR program starts. Its VALUE is the
 * current date and time.
 * 
 * E (end).  Sent when the AUR program is done. VALUE is the current date and
 * time.  AUR may close its end of the socket immediately after sending this
 * message; it need not wait.
 * 
 * C (cd): Sent when the current directory is read or changed.
 * 
 * A (add). Sent when a file is added to the repository. VALUE is the full,
 * absolute path to the file.
 * 
 * U (update). Sent when a file is updated in the repository, e.g. the
 * contents change but the filename remains the same and is in the same
 * directory.
 * 
 * R (remove). Sent when a file is removed from the repository.  VALUE is the
 * full path to the file.
 * 
 * L (link). Sent when a link (hard or symbolic) is made between two files in
 * the repository. VALUE is formed as follows: "filename1" SP filename2.
 * Filename1 is a full pathname in double quotes; it is followed by a single
 * space, and then filename2 which is also a full pathname. The link direction 
 * is filename1 -> filename2.
 * 
 * F (fatal error). Sent (if possible) when the AUR program detects an
 * unrecoverable error occurs. VALUE is the error text. It is expected that
 * AUR will immediately close its end of the socket when this happens (perhaps 
 * even without being able to send an E message).
 * 
 * X (error). Sent when an error occurs. VALUE is error text.  This is an
 * optional message.
 * 
 * W (warning). Sent when a warning occurs. VALUE is warning text. Optional
 * message.
 * 
 * S (save state). Sent when it makes sense to save the state
 * 
 * V (restore state). Sent when it makes sense to restore the state
 * 
 * I (information). Sent to convey arbitrary information.  VALUE is the
 * informational text. Optional message. 
 */

static int sockline(
    scm * scmp,
    scmcon * conp,
    int s)
{
    char *left = NULL;
    char *ptr;
    char *valu;
    char c;
    int done = 0;
    int sta = 0;

    for (done = 0; !done;)
    {
        /*
         * If we are in blocking mode, probe() is unnecessary. Commented out
         * by A. Chi, 3/18/11. 
         */
        /*
         * if ( (sta=probe(s)) < 0 ) { LOG(LOG_ERR, "Probe error %d",
         * sta); return(sta); } 
         */
        sta = sock1line(s, &left, &ptr);
        if (sta != 0)
            return sta;
        if (ptr == NULL)
            continue;
        LOG(LOG_INFO, "Sockline: %s", ptr);
        c = ptr[0];
        if (!isspace((int)(unsigned char)(ptr[1])))
        {
            LOG(LOG_ERR, "Invalid line: ignored");
            free((void *)ptr);
            continue;
        }
        valu = afterwhite(ptr + 1);
        switch (c)
        {
        case 'b':              /* begin */
        case 'B':
            LOG(LOG_INFO, "AUR beginning at %s", valu);
            break;
        case 'e':
        case 'E':              /* end */
            LOG(LOG_INFO, "AUR ending at %s", valu);
            done = 1;
            break;
        case 'c':
        case 'C':              /* cd */
            if (hdir != NULL)
            {
                free((void *)hdir);
                hdir = NULL;
            }
            hdir = strdup(valu);
            break;
        case 'a':
        case 'A':              /* add */
            LOG(LOG_INFO, "AUR add request: %s", valu);
            sta = aur(scmp, conp, 'a', valu);   // , splitOnWhite(valu));
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'u':
        case 'U':              /* update */
            LOG(LOG_INFO, "AUR update request: %s", valu);
            sta = aur(scmp, conp, 'u', valu);   // , splitOnWhite(valu));
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'r':
        case 'R':              /* remove */
            LOG(LOG_INFO, "AUR remove request: %s", valu);
            sta = aur(scmp, conp, 'r', valu);   // , NULL);
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'l':
        case 'L':              /* link */
            LOG(LOG_INFO, "AUR link request: %s", valu);
            break;
        case 'f':
        case 'F':              /* fatal error */
            LOG(LOG_INFO, "AUR fatal error: %s", valu);
            done = 1;
            break;
        case 'x':
        case 'X':              /* error */
            LOG(LOG_ERR, "AUR error: %s", valu);
            break;
        case 'w':
        case 'W':              /* warning */
            LOG(LOG_WARNING, "AUR warning: %s", valu);
            break;
        case 'i':
        case 'I':              /* information */
            LOG(LOG_INFO, "AUR message: %s", valu);
            break;
        case 's':
        case 'S':              /* save */
            (void)saveState(conp, scmp);
            break;
        case 'v':
        case 'V':              /* restore */
            (void)restoreState(conp, scmp);
            break;
        case 'y':
        case 'Y':              /* synchronize */
            (void)write(s, "Y", 1);
            break;
        case 0:
            break;
        default:
            LOG(LOG_INFO, "AUR invalid tag '%c' ignored", c);
            break;
        }
        free((void *)ptr);
    }
    free((void *)left);
    return (sta);
}

static int fileline(
    scm * scmp,
    scmcon * conp,
    FILE * s)
{
    // char *left = NULL;
    char ptr[1024];
    char *valu;
    char c;
    int done = 0;
    int sta = 0;

    for (done = 0; !done;)
    {
        if (fgets(ptr, 1023, s) == NULL)
            break;
        char *cp;
        for (cp = ptr; *cp >= ' '; cp++);
        *cp = 0;                // trim off CR/LF
        LOG(LOG_INFO, "Sockline: %s", ptr);
        c = ptr[0];
        if (!isspace((int)(unsigned char)(ptr[1])))
        {
            LOG(LOG_ERR, "Invalid line: ignored");
            continue;
        }
        valu = afterwhite(ptr + 1);
        switch (c)
        {
        case 'b':              /* begin */
        case 'B':
            LOG(LOG_INFO, "AUR beginning at %s", valu);
            break;
        case 'e':
        case 'E':              /* end */
            LOG(LOG_INFO, "AUR ending at %s", valu);
            done = 1;
            break;
        case 'c':
        case 'C':              /* cd */
            if (hdir != NULL)
            {
                free((void *)hdir);
                hdir = NULL;
            }
            hdir = strdup(valu);
            break;
        case 'a':
        case 'A':              /* add */
            LOG(LOG_INFO, "AUR add request: %s", valu);
            sta = aur(scmp, conp, 'a', valu);   // , splitOnWhite(valu));
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'u':
        case 'U':              /* update */
            LOG(LOG_INFO, "AUR update request: %s", valu);
            sta = aur(scmp, conp, 'u', valu);   // , splitOnWhite(valu));
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'r':
        case 'R':              /* remove */
            LOG(LOG_INFO, "AUR remove request: %s", valu);
            sta = aur(scmp, conp, 'r', valu);   // , NULL);
            if (sta < 0)
                LOG(LOG_ERR, "Status was %d (%s)", sta, err2string(sta));
            else
                LOG(LOG_DEBUG, "Status was %d", sta);
            break;
        case 'l':
        case 'L':              /* link */
            LOG(LOG_INFO, "AUR link request: %s", valu);
            break;
        case 'f':
        case 'F':              /* fatal error */
            LOG(LOG_ERR, "AUR fatal error: %s", valu);
            done = -1;
            break;
        case 'x':
        case 'X':              /* error */
            LOG(LOG_ERR, "AUR error: %s", valu);
            break;
        case 'w':
        case 'W':              /* warning */
            LOG(LOG_WARNING, "AUR warning: %s", valu);
            break;
        case 'i':
        case 'I':              /* information */
            LOG(LOG_INFO, "AUR message: %s", valu);
            break;
        case 's':
        case 'S':              /* save */
            (void)saveState(conp, scmp);
            break;
        case 'v':
        case 'V':              /* restore */
            (void)restoreState(conp, scmp);
            break;
        case 'y':
        case 'Y':              /* synchronize */
            // (void)write(s, "Y", 1);
            break;
        case 0:
            break;
        default:
            LOG(LOG_INFO, "AUR invalid tag '%c' ignored", c);
            break;
        }
    }
    return (sta);
}

// putative command line args:
// -t topdir create all tables, set rep root to "topdir"
// -x destroy all tables
// -y force operation, don't ask
// -h print help
// -d object delete the given object
// -f file add the given object
// -F file add the given trusted object
// -w port operate in wrapper mode using the given socket port
// -p with -w indicates to run perpetually, e.g. as a daemon
// -z run from file list instead of port
// -c use RP work

int main(
    int argc,
    char **argv)
{
    scmcon *testconp = NULL;
    scmcon *realconp = NULL;
    scm *scmp = NULL;
    FILE *sfile = NULL;
    char *thedelfile = NULL;
    char *topdir = NULL;
    char *thefile = NULL;
    char *outfile = NULL;
    char *outfull = NULL;
    char *outdir = NULL;
    char *tmpdsn = NULL;
    char *ne;
    char *porto = NULL;
    char errmsg[1024];
    char *skifile = NULL;
    int ians = 0;
    int do_create = 0;
    int do_delete = 0;
    int do_sockopts = 0;
    int do_fileopts = 0;
    int perpetual = 0;
    int really = 0;
    int trusted = 0;
    int force = 0;
    int allowex = 0;
    int sta = 0;
    int s;
    int c;

    (void)setbuf(stdout, NULL);
    if (argc <= 1)
    {
        usage();
        return (1);
    }
    while ((c = getopt(argc, argv, "t:xyhad:f:F:wz:pm:c:s")) != EOF)
    {
        switch (c)
        {
        case 'a':
            allowex = 1;
            break;
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
            break;
        case 'z':
            do_fileopts++;
            porto = optarg;
            break;
        case 'p':
            perpetual++;
            break;
        case 'c':
            skifile = optarg;
            break;
        case 'h':
            usage();
            return (0);
        case 's':
            strict_profile_checks = 1;  // global from myssl.c
            strict_profile_checks_cms = 1;      // global from roa_validate.c
            break;
        default:
            (void)fprintf(stderr, "Invalid option '%c'\n", c);
            usage();
            return (1);
        }
    }
    // if there is anything left in argv, or no operation specified, warn user
    if (optind < argc)
    {
        (void)printf("Extra arguments at the end of the command line.\n");
        usage();
        return (1);
    }
    if ((do_create + do_delete + do_sockopts + do_fileopts) == 0 &&
        thefile == 0 && thedelfile == 0 && skifile == 0)
    {
        (void)printf("You need to specify at least one operation "
                     "(e.g. -f file).\n");
        usage();
        return (1);
    }
    OPEN_LOG("rcli", LOG_USER);
    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't load configuration");
        exit(EXIT_FAILURE);
    }
    if (force == 0)
    {
        if (do_delete > 0)
        {
            ians = yorn("Do you REALLY want to delete all database tables");
            if (ians <= 0)
            {
                LOG(LOG_NOTICE, "Delete operation cancelled");
                return (1);
            }
            really++;
        }
        if ((do_create > 0) && (really == 0))
        {
            ians = yorn("Do you REALLY want to create all database tables");
            if (ians <= 0)
            {
                LOG(LOG_NOTICE, "Create operation cancelled");
                return (1);
            }
            really++;
        }
    }
    scmp = initscm();
    if (scmp == NULL)
    {
        LOG(LOG_ERR, "Internal error: cannot initialize database schema");
        return (-2);
    }
    /*
     * If a create or delete operation is being performed, then a test dsn
     * will be needed; create it now and defer the creation of the real dsn
     * until later. Otherwise, create the real dsn.
     * 
     * A test dsn is needed for operations that operate on the overall
     * database state as opposed to the rpki tables, namely the create and
     * delete operations.
     */
    if ((do_create + do_delete) > 0)
    {
        /*
         * Note that in the following line, we do not intend to edit
         * the database named "information_schema".  We are simply
         * filling in the "database name" parameter with something
         * that is guaranteed to be valid for MySQL.
         */
        tmpdsn = makedsnscm(scmp->dsnpref, "information_schema",
                            CONFIG_DATABASE_USER_get(),
                            CONFIG_DATABASE_PASSWORD_get());
        if (tmpdsn == NULL)
        {
            membail();
            return (-1);
        }
        testconp = connectscm(tmpdsn, errmsg, 1024);
        memset(tmpdsn, 0, strlen(tmpdsn));
        free((void *)tmpdsn);
        if (testconp == NULL)
        {
            LOG(LOG_ERR, "Cannot connect to DSN: %s", errmsg);
            freescm(scmp);
            return (-1);
        }
    }
    else
    {
        realconp = connectscm(scmp->dsn, errmsg, 1024);
        if (realconp == NULL)
        {
            LOG(LOG_ERR, "Cannot connect to DSN %s: %s", scmp->dsn,
                    errmsg);
            freescm(scmp);
            return (-1);
        }
    }
    /*
     * Process command line options in the following order: delete, create,
     * dofile, dodir, listener. 
     */
    if (do_delete > 0)
        sta = deleteop(testconp, scmp);
    if ((do_create > 0) && (sta == 0))  /* first phase of create */
        sta = createop(testconp, scmp);
    /*
     * Don't need the test connection any more 
     */
    if (testconp != NULL)
    {
        disconnectscm(testconp);
        testconp = NULL;
    }
    /*
     * If there has been an error or if we're done because the database was
     * just deleted and not re-created, bail out.
     */
    if (sta < 0 || (do_delete > 0 && do_create == 0))
    {
        if (realconp != NULL)
            disconnectscm(realconp);
        freescm(scmp);
        if (tdir != NULL)
            free((void *)tdir);
        return (sta);
    }
    /*
     * If a connection to the real DSN has not been opened yet, open it now. 
     */
    if (realconp == NULL)
    {
        realconp = connectscm(scmp->dsn, errmsg, 1024);
        if (realconp == NULL)
        {
            LOG(LOG_ERR, "Cannot connect to DSN %s: %s",
                scmp->dsn, errmsg);
            freescm(scmp);
            if (tdir != NULL)
                free((void *)tdir);
            return (-1);
        }
    }
    /*
     * If a create operation was requested, complete it now. 
     */
    if ((do_create > 0) && (sta == 0))
        sta = create2op(scmp, realconp, topdir);
    /*
     * If the top level repository directory is not set, then retrieve it from
     * the database. 
     */
    if ((tdir == NULL) && (sta == 0))
    {
        tdir = retrieve_tdir(scmp, realconp, &sta);
        if (tdir == NULL)
            LOG(LOG_ERR,
                    "Cannot retrieve top level repository info from DB");
    }
    if (sta == 0)
    {
        LOG(LOG_INFO, "Top level repository directory is %s", tdir);
        tdirlen = strlen(tdir);
    }
    /*
     * Setup for actual SSL operations 
     */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    LOG(LOG_NOTICE, "Rsync client session started");
    if (thefile != NULL && sta == 0)
    {
        // Check that the file is in the repository, ask if not and force is
        // off
        sta = splitdf(NULL, NULL, thefile, &outdir, &outfile, &outfull);
        if (sta == 0)
        {
            if (strncmp(tdir, outdir, tdirlen) != 0 && force == 0)
            {
                ians =
                    yorn("That file is not in the repository. Proceed anyway");
                if (ians <= 0)
                    sta = 1;
            }
            // if ( strstr(outdir, "TRUST") != NULL )
            // trusted++;
            // if the user has declared it to be trusted
            // ask for verification unless force is set
            if (trusted > 0 && force == 0 && sta == 0)
            {
                ians = yorn("Really declare this file as trusted");
                if (ians <= 0)
                    sta = 1;
            }
            if (sta == 1)
                LOG(LOG_NOTICE, "File operation cancelled");
            if (sta == 0)
            {
                LOG(LOG_INFO, "Attempting to add file %s", outfile);
                setallowexpired(allowex);
                sta = add_object(scmp, realconp, outfile, outdir, outfull,
                                 trusted);
                if (sta < 0)
                {
                    LOG(LOG_ERR,
                            "Could not add file %s: error %s (%d)",
                            thefile, err2string(sta), sta);
                    if (sta == ERR_SCM_SQL)
                    {
                        ne = geterrorscm(realconp);
                        if (ne != NULL && ne != 0)
                            LOG(LOG_ERR, "\t%s", ne);
                    }
                }
                else
                    LOG(LOG_INFO, "Add operation succeeded");
            }
            free((void *)outdir);
            free((void *)outfile);
            free((void *)outfull);
        }
        else
            LOG(LOG_ERR, "Error: %s (%d)", err2string(sta), sta);
    }
    if (thedelfile != NULL && sta == 0)
    {
        sta = splitdf(NULL, NULL, thedelfile, &outdir, &outfile, &outfull);
        if (sta == 0)
        {
            sta = delete_object(scmp, realconp, outfile, outdir, outfull, 0);
            if (sta < 0)
            {
                LOG(LOG_ERR,
                        "Could not delete file %s: error %s (%d)",
                        thedelfile, err2string(sta), sta);
                if (sta == ERR_SCM_SQL)
                {
                    ne = geterrorscm(realconp);
                    if (ne != NULL && ne != 0)
                        LOG(LOG_ERR, "\t%s", ne);
                }
            }
            else
                LOG(LOG_INFO, "Delete operation succeeded (%s removed)",
                        thedelfile);
            free((void *)outdir);
            free((void *)outfile);
            free((void *)outfull);
        }
        else
            LOG(LOG_ERR, "Error: %s (%d)", err2string(sta), sta);
    }
    if ((do_sockopts + do_fileopts) > 0 && sta == 0)
    {
        int protos = (-1);
        const int max_makesock_attempts = 10;
        int makesock_failures = 0;
        do
        {
            if (do_sockopts > 0)
            {
                uint16_t port = CONFIG_RPKI_PORT_get();
                s = makesock(port, &protos);
                if (s < 0)
                {
                    makesock_failures++;
                    LOG(LOG_ERR,
                            "Failed to listen on port %" PRIu16 " (failure #%d)", port,
                            makesock_failures);
                    sleep(1);
                    if (makesock_failures >= max_makesock_attempts)
                    {
                        LOG(LOG_ERR,
                                "%d failed attempts to create socket. Aborting.",
                                max_makesock_attempts);
                        sta = -1;
                        break;
                    }
                }
                else
                {
                    makesock_failures = 0;
                    FLUSH_LOG();
                    sta = sockline(scmp, realconp, s);
                    LOG(LOG_INFO, "Socket connection closed");
                    FLUSH_LOG();
                    (void)close(s);
                }
            }
            if (do_fileopts > 0 && porto != NULL)
            {
                if (!isatty(0))
                {
                    LOG(LOG_DEBUG, "Opening stdin");
                    sfile = stdin;
                    sta = fileline(scmp, realconp, sfile);
                }
                else
                {
                    LOG(LOG_DEBUG, "Opening a socket cmdfile %s", porto);
                    sfile = fopen(porto, "r");
                    if (sfile == NULL)
                        LOG(LOG_ERR, "Could not open cmdfile");
                    else
                    {
                        sta = fileline(scmp, realconp, sfile);
                        LOG(LOG_DEBUG, "Cmdfile closed");
                        (void)fclose(sfile);
                    }
                }
            }
            if (sta == 0 && skifile)
            {
                LOG(LOG_DEBUG, "Starting skifile %s", skifile);
                sta = read_SKI_blocks(scmp, realconp, skifile);
                if (sta > 0)
                    sta = 0;
                if (sta)
                    LOG(LOG_ERR, "Error with skifile: %s (%d)",
                            err2string(sta), sta);
            }
        } while (perpetual > 0);
        if (protos >= 0)
            (void)close(protos);
    }
    if (sta == 0 && skifile)
    {
        LOG(LOG_DEBUG, "Starting skifile %s", skifile);
        sta = read_SKI_blocks(scmp, realconp, skifile);
        if (sta > 0)
            sta = 0;
        if (sta)
            LOG(LOG_ERR, "Error with skifile: %s (%d)", err2string(sta),
                    sta);
    }
    (void)ranlast(scmp, realconp, "RSYNC");
    sqcleanup();
    if (realconp != NULL)
        disconnectscm(realconp);
    freescm(scmp);
    if (tdir != NULL)
        free((void *)tdir);
    LOG(LOG_NOTICE, "Rsync client session ended");
    config_unload();
    CLOSE_LOG();
    return (sta);
}
