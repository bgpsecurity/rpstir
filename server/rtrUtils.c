
/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

#include "rtrUtils.h"
#include "err.h"
#include <stdio.h>
#include <stdlib.h>

// for passing back results
static uint lastSerialNum, recentSerialNums[1024], returnSNs[1024];
static uint numRecent, origSN, foundOrig;

static scmsrcha *snSrch = NULL;
static scmtab   *updateTable = NULL;

static void setupQuery(scm *scmp) {
	snSrch = newsrchscm(NULL, 1, 0, 1);
	addcolsrchscm(snSrch, "serial_num", SQL_C_ULONG, 8);
	snSrch->wherestr = NULL;
	updateTable = findtablescm(scmp, "rtr_update");
	if (updateTable == NULL) printf("Cannot find table rtr_update\n");
}

/* helper function for getLastSerialNumber */
static int setLastSN(scmcon *conp, scmsrcha *s, int numLine) {
	lastSerialNum = *((uint *) (s->vec[0].valptr));
	return -1;    // stop after first row
}

/****
 * find the serial number from the most recent update
 ****/
uint getLastSerialNumber(scmcon *connect, scm *scmp) {
	lastSerialNum = 0;
	if (snSrch == NULL) setupQuery(scmp);
	searchscm (connect, updateTable, snSrch, NULL, setLastSN,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_BREAK_VERR,
			   "create_time desc");
	return lastSerialNum;
}

/* helper function for getMostRecentSerialNums */
static int setRecentSNs(scmcon *conp, scmsrcha *s, int numLine) {
	uint serialNum = *((uint *) (s->vec[0].valptr));
	if (serialNum == origSN) {
		foundOrig = 1;
		return -1;  // stop the search
	}
	recentSerialNums[numRecent] = serialNum;
	numRecent++;
	return 1;
}

uint* getMoreRecentSerialNums(scmcon *connect, scm *scmp, uint serialNum) {
	int i;
	numRecent = 0;
	foundOrig = 0;
	origSN = serialNum;
	if (snSrch == NULL) setupQuery(scmp);
	searchscm (connect, updateTable, snSrch, NULL, setRecentSNs,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_BREAK_VERR,
			   "create_time desc");
	if (! foundOrig) return NULL;
	for (i = 0; i < numRecent; i++)
		returnSNs[i] = recentSerialNums[numRecent - 1 - i];
	returnSNs[numRecent] = 0;
	return returnSNs;
}

