
/*
 * $Id: query.c 857 2009-09-30 15:27:40Z dmontana $ 
 */

/****************
 * Functions and flags shared by query and server code
 ****************/

/****
 * routine to parse the filter specification file which  determines how to
 * handle the various meta-data SCM_FLAG_XXX flags (ignore, matchset, matchclr)
 * - Returns 0 on success, -1 on failure
 ****/
extern int parseStalenessSpecsFile(
    char *specsFilename);

/*****
 * read out the values from parsing the staleness specs
 *****/
extern void getSpecsVals(
    int *rejectStaleChainp,
    int *rejectStaleManifestp,
    int *rejectStaleCRLp,
    int *rejectNoManifestp,
    int *rejectNotYetp);

/******
 * put the appropriate tests for SCM_FLAG_XXX flags in the where
 *   string of a query
 ******/
extern void addQueryFlagTests(
    char *whereStr,
    int needAnd);

/****** prototype for a function for displaying a field *****/
typedef int (
    *displayfunc) (
    scmsrcha * s,
    int idx1,
    char *returnStr);

/******
 * attributes of a field to display or filter on
 ******/
typedef struct _QueryField {
    char *name;                 /* name of the field */
    char *description;          /* one-line description for user help */
    int flags;                  /* flags (see Q_xyz above) */
    int sqlType;                /* what type of data to expect from query */
    int maxSize;                /* how much space to allocate for response */
    char *dbColumn;             /* if not NULL, use this for query, not name */
    char *otherDBColumn;        /* if not NULL, second field for query */
    char *heading;              /* name of column heading to use in printout */
    displayfunc displayer;      /* function for display string, NULL if std */
} QueryField;

/******
 * Find the attributes of a particular field to query on
 ******/
extern QueryField *findField(
    char *name);

/******
 * The set of all the fields
 ******/
extern QueryField *getFields(
    void);

/******
 * The total number of fields
 ******/
extern int getNumFields(
    void);

/*****
 * check the valdity via the db of the cert whose ski or localID is given
 *****/
extern int checkValidity(
    char *ski,
    unsigned int localID,
    scm * scmp,
    scmcon * connect);

/*****
 * displayFlags function needs to know if object is a manifes
 *****/
void setIsManifest(
    int val);

#define Q_JUST_DISPLAY  0x01
#define Q_FOR_ROA       0x02
#define Q_FOR_CRL       0x04
#define Q_FOR_CERT      0x08
#define Q_REQ_JOIN	0x10
#define Q_FOR_MAN       0x20

#define MAX_RESULT_SZ 8192
