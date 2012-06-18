/*
 * $Id$ 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "scm.h"
#define  SCM_DEFINED_HERE
#include "scmmain.h"
#undef   SCM_DEFINED_HERE


/*
 * Free all the memory allocated in building an scm 
 */

static void freescmtable(
    scmtab * tabp)
{
    int i;

    if (tabp == NULL)
        return;
    if (tabp->tabname != NULL)
    {
        free((void *)(tabp->tabname));
        tabp->tabname = NULL;
    }
    if (tabp->hname != NULL)
    {
        free((void *)(tabp->hname));
        tabp->hname = NULL;
    }
    if (tabp->tstr != NULL)
    {
        free((void *)(tabp->tstr));
        tabp->tstr = NULL;
    }
    if (tabp->cols == NULL)
        return;
    for (i = 0; i < tabp->ncols; i++)
    {
        if (tabp->cols[i] != NULL)
        {
            free((void *)(tabp->cols[i]));
            tabp->cols[i] = NULL;
        }
    }
    free((void *)(tabp->cols));
    tabp->cols = NULL;
}

void freescm(
    scm * scmp)
{
    int i;

    if (scmp == NULL)
        return;
    if (scmp->db != NULL)
    {
        free((void *)(scmp->db));
        scmp->db = NULL;
    }
    if (scmp->dbuser != NULL)
    {
        free((void *)(scmp->dbuser));
        scmp->dbuser = NULL;
    }
    if (scmp->dbpass != NULL)
    {
        free((void *)(scmp->dbpass));
        scmp->dbpass = NULL;
    }
    if (scmp->dsnpref != NULL)
    {
        free((void *)(scmp->dsnpref));
        scmp->dsnpref = NULL;
    }
    if (scmp->dsn != NULL)
    {
        free((void *)(scmp->dsn));
        scmp->dsn = NULL;
    }
    if (scmp->tables != NULL)
    {
        for (i = 0; i < scmp->ntables; i++)
            freescmtable(&scmp->tables[i]);
        free((void *)(scmp->tables));
        scmp->tables = NULL;
    }
    free((void *)scmp);
}

/*
 * Find a column name in a schema line. Column names that appear to begin with 
 * non-whitespace are considered to be values; other columns are considered to 
 * be modifiers (e.g. designation of a key). 
 */

static char *firsttok(
    char *ptr)
{
    char *run;
    char *out;
    char c;
    int cnt = 0;

    if (ptr == NULL || ptr[0] == 0)
        return (NULL);
    run = ptr;
    while (1)
    {
        c = *run++;
        if (isspace((int)(unsigned char)c) || c == 0)
            break;
        cnt++;
    }
    if (cnt == 0)
        return (NULL);
    out = (char *)calloc(cnt + 1, sizeof(char));
    if (out == NULL)
        return (NULL);
    (void)strncpy(out, ptr, cnt);
    out[cnt] = 0;
    return (out);
}

/*
 * Parse the schema and build a list of columns. 
 */

static int makecolumns(
    scmtab * outtab)
{
    char *ptr;
    char *dp;
    int rcnt = 0;
    int cnt = 0;

    if (outtab == NULL || outtab->tstr == NULL)
        return (-1);
    // if the tstr is the zero-length string "" then do nothing
    if (outtab->tstr[0] == 0)
        return (0);
    dp = strdup(outtab->tstr);
    if (dp == NULL)
        return (-2);
    ptr = strtok(dp, ",");
    while (ptr != NULL && ptr[0] != 0)
    {
        if (islower((int)(unsigned char)(ptr[0]))
            && !isspace((int)(unsigned char)(ptr[0])))
            cnt++;
        ptr = strtok(NULL, ",");
    }
    free(dp);
    outtab->cols = (char **)calloc(cnt, sizeof(char *));
    if (outtab->cols == NULL)
        return (-3);
    dp = strdup(outtab->tstr);
    if (dp == NULL)
        return (-4);
    ptr = strtok(dp, ",");
    while (ptr != NULL && ptr[0] != 0 && rcnt < cnt)
    {
        if (!islower((int)(unsigned char)(ptr[0]))
            || isspace((int)(unsigned char)(ptr[0])) || ptr[0] == 0)
            break;
        outtab->cols[rcnt] = firsttok(ptr);
        if (outtab->cols[rcnt] == NULL)
        {
            free(dp);
            return (-rcnt - 5);
        }
        rcnt++;
        ptr = strtok(NULL, ",");
    }
    free(dp);
    outtab->ncols = rcnt;
    return (0);
}

/*
 * Build the data structure associated with a single table. 
 */

static int prepareonetable(
    scmtab * outtab,
    scmtab * intab)
{
    int sta;

    if (outtab == NULL || intab == NULL)
        return (-1);
    outtab->tabname = strdup(intab->tabname);
    if (outtab->tabname == NULL)
        return (-2);
    outtab->hname = strdup(intab->hname);
    if (outtab->hname == NULL)
        return (-3);
    outtab->tstr = strdup(intab->tstr);
    if (outtab->tstr == NULL)
        return (-4);
    sta = makecolumns(outtab);
    return (sta);
}

/*
 * Build the data structure associated with the entire set of tables. 
 */

static int preparetables(
    scm * scmp,
    scmtab * scmtabbuilderp,
    int sz)
{
    int cnt = 0;
    int sta;
    int i;

    if (scmp == NULL || scmtabbuilderp == NULL || sz <= 0)
        return (-1);
    scmp->tables = (scmtab *) calloc(sz, sizeof(scmtab));
    if (scmp->tables == NULL)
        return (-2);
    for (i = 0; i < sz; i++)
    {
        sta = prepareonetable(&scmp->tables[i], &scmtabbuilderp[i]);
        if (sta < 0)
            return (sta);
        cnt++;
    }
    scmp->ntables = cnt;
    return (0);
}

/*
 * Make a complete DSN name based on a prefix, the name of a database, the
 * name of a user of that database, and an optional password. 
 */

char *makedsnscm(
    char *pref,
    char *db,
    char *usr,
    char *pass)
{
    char *ptr;
    int len;

    if (pref == NULL || db == NULL || usr == NULL ||
        pref[0] == 0 || db[0] == 0 || usr[0] == 0)
        return (NULL);
    len = strlen(pref) + strlen(db) + strlen(usr) + 60;
    if (pass != NULL && pass[0] != 0)
        len += strlen(pass);
    ptr = (char *)calloc(len + 1, sizeof(char));
    if (ptr == NULL)
        return (NULL);
    if (pass == NULL || pass[0] == 0)
        (void)snprintf(ptr, len, "DSN=%s;DATABASE=%s;UID=%s", pref, db, usr);
    else
        (void)snprintf(ptr, len, "DSN=%s;DATABASE=%s;UID=%s;PASSWORD=%s",
                       pref, db, usr, pass);
    return (ptr);
}

/*
 * Initialize the schema data structure. 
 */

scm *initscm(
    void)
{
    scm *scmp;
    int sta;
    char *db = getenv("RPKI_DB");
    char *dbu = getenv("RPKI_DBUSER");
    char *dbp = getenv("RPKI_DBPASS");
    char *dsn = getenv("RPKI_DSN");

    scmp = (scm *) calloc(1, sizeof(scm));
    if (scmp == NULL)
        return (NULL);
    scmp->db = strdup((db == NULL) ? RPKI_DB : db);
    if (scmp->db == NULL)
    {
        freescm(scmp);
        return (NULL);
    }
    scmp->dbuser = strdup((dbu == NULL) ? RPKI_DBUSER : dbu);
    if (scmp->dbuser == NULL)
    {
        freescm(scmp);
        return (NULL);
    }
    // password is allowed to be NULL
    if (dbp != NULL)
        scmp->dbpass = strdup(dbp);
    else
    {
        if (RPKI_DBPASS != NULL)
            scmp->dbpass = strdup(RPKI_DBPASS);
    }
    scmp->dsnpref = strdup((dsn == NULL) ? RPKI_DSN : dsn);
    if (scmp->dsnpref == NULL)
    {
        freescm(scmp);
        return (NULL);
    }
    scmp->dsn =
        makedsnscm(scmp->dsnpref, scmp->db, scmp->dbuser, scmp->dbpass);
    if (scmp->dsn == NULL)
    {
        freescm(scmp);
        return (NULL);
    }
    sta = preparetables(scmp, &scmtabbuilder[0],
                        sizeof(scmtabbuilder) / sizeof(scmtab));
    if (sta < 0)
    {
        freescm(scmp);
        return (NULL);
    }
    return (scmp);
}

/*
 * Given the nice name for a table, return a pointer to the data structure
 * describing that table, or NULL if no match can be found. 
 */

scmtab *findtablescm(
    scm * scmp,
    char *hname)
{
    char *ptr;
    int i;

    if (scmp == NULL || hname == NULL || hname[0] == 0 ||
        scmp->ntables <= 0 || scmp->tables == NULL)
        return (NULL);
    for (i = 0; i < scmp->ntables; i++)
    {
        ptr = scmp->tables[i].hname;
        if (ptr != NULL && ptr[0] != 0 && strcasecmp(ptr, hname) == 0)
            return (&scmp->tables[i]);
    }
    return (NULL);
}

#ifdef TEST

int main(
    void)
{
    scm *scmp;
    int i;
    int j;

    (void)setbuf(stdout, NULL);
    scmp = initscm();
    (void)printf("DSN name is %s\n", scmp->dsn);
    (void)printf("Number of tables is %d\n", scmp->ntables);
    for (i = 0; i < scmp->ntables; i++)
    {
        (void)printf("%d\t%s\t%s\n", i + 1,
                     scmp->tables[i].tabname, scmp->tables[i].hname);
        (void)printf("    Table columns: %d\n\t", scmp->tables[i].ncols);
        for (j = 0; j < scmp->tables[i].ncols; j++)
            (void)printf(" %s", scmp->tables[i].cols[j]);
        (void)printf("\n");
    }
    return (0);
}

#endif
