#include <stdio.h>
// #include <linux/limits.h>
#include "parse.h"
#include "main.h"

/*
 * $Id$ 
 */


static const char *WHITESPACE = "\n\r\t ";

/*
 * Copy the directory string for a particular path to the destination buffer.
 * A path which ends in '/' will simply be copied, whereas a path with no '/'
 * returns the string ".".  At most dest_len characters will be copied,
 * including the terminating '\0'.  If dest_len was not enough space, a NULL
 * is returned. 
 */
static char *dirname(
    char *dest,
    int dest_len,
    const char *path)
{
    const char *right_most_slash;
    int dir_length;

    if (!path)
        return NULL;

    /*
     * Search for right-most slash. 
     */
    right_most_slash = strrchr(path, '/');
    if (!right_most_slash)
    {
        if (dest_len < 2)
            return NULL;
        else
            return strcpy(dest, ".");
    }

    /*
     * Copy directory substring, terminating with null. 
     */
    dir_length = right_most_slash - path + 1;
    if (dir_length > dest_len - 1)
        return NULL;
    strncpy(dest, path, dir_length);
    dest[dir_length] = '\0';

    return dest;
}


/**************************************************************
 * function: getMessageFromString(char *, unsigned int len,   *
 *              unsigned int *retlen, char flags)             *
 * returns: char *                                            *
 *                                                            *
 * input is a char * to a line from the log file, the length  *
 *   of the char * string, pointer to returned str len        *
 *     and a verbose value                                    *
 *                                                            *
 * It is expected that this function will be called in from   *
 * within a while(fgets(... call. The char buffer should      *
 * be at least PATH_MAX                                       *
 *                                                            *
 * The string that is being parsed is expected to be from     *
 *  an rsync itemized changes output logfile  ( rsync flags   *
 *  '-i' or '--itemize-changes' only ). This means that we    *
 * are expecting the default outformat of "%i %n%L" from      *
 * rsync.                                                     *
 *                                                            *
 * The flags value will specify how unknown or ancillary      *
 * info will be handled. A value of 0 means that error and    *
 * information data will be ignored and the function should   *
 * return NULL (remember it's in an fgets() loop and anything *
 * sent from the output of this should make sure it is !NULL) *
 * if it does not know what to do with a line.                *
 *                                                            *
 * XXX - TODO                                                 *
 *  there really needs to be a sanity check to make sure that *
 *  the string being read in (or handed in) ends in '\n'.     *
 *  Possibly introducing a '\n' if not there or else error    *
 *  that the string is not in the correct format (ends in \n).*
 *************************************************************/
char *getMessageFromString(
    const char *str,
    unsigned int len,
    unsigned int *retlen,
    char flags)
{
    unsigned char Y,
        X;
    char *retStr = NULL;

    /*
     * len < 2 so we are sure that we have at least YX or '*\ ' for parsing 
     */

    if ((!str) || (len < 2))
        return (NULL);

    Y = (unsigned char)*str;
    X = (unsigned char)*(str + 1);

    switch (Y)
    {
    case '*':
        /*
         * deletion event 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        /*
         * looks OK - create and return REMOVE 
         */
        retStr = makeRemoveStr(str, len, retlen);
        return (retStr);
        break;
    case '<':
        /*
         * transfer to remote host 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        /*
         * we passed the looksOK test - if flags wants INFO then return an
         * INFO str, else return NULL 
         */
        if (flags & INFO_FLAG)
        {
            retStr = makeInfoStr(str, len, retlen);
            return (retStr);
        }
        else
        {
            return (NULL);
        }
        break;
    case '>':
        /*
         * transfer to local host (receiving file) 
         */
        /*
         * this is what we are primarily interested in 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        const char *bitFlags = (str + 2);       /* skip >f */
        const char *addStr = "+++++++"; /* rsync 3.x still works w/ this */
        if (strncmp(bitFlags, addStr, 7) == 0)
            retStr = makeAddStr(str, len, retlen);
        else
            retStr = makeUpdateStr(str, len, retlen);
        return (retStr);
        break;
    case 'c':
        /*
         * change/creation (directory or symlink) 
         */
        /*
         * transfer to remote host 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        /*
         * we passed the looksOK test - if this is a change specifying a
         * symlink then create a link message 
         */
        if (X == 'L')
        {
            retStr = makeLinkStr(str, len, retlen);
            return (retStr);
        }
        /*
         * it looksOK, it's not a Link, so if verbose wants INFO strings make
         * one and return it, otherwise return(NULL); 
         */
        if (flags & INFO_FLAG)
        {
            retStr = makeInfoStr(str, len, retlen);
            return (retStr);
        }
        else
        {
            return (NULL);
        }
        break;
    case 'h':
        /*
         * hard link to another element 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        /*
         * passed the looksOK test 
         */
        retStr = makeLinkStr(str, len, retlen);
        return (retStr);
        break;
    case '.':
        /*
         * not being updated - possible attribute change 
         */
        if (looksOK(str, len) != TRUE)
        {
            if (flags & WARNING_FLAG)
            {
                retStr = makeWarningStr(str, len, retlen);
                return (retStr);
            }
            else
            {
                return (NULL);
            }
        }
        if (flags & INFO_FLAG)
        {
            retStr = makeInfoStr(str, len, retlen);
            return (retStr);
        }
        else
        {
            return (NULL);
        }
        break;
    default:
        /*
         * unknown - send as WARNING 
         */
        if (flags & ERROR_FLAG)
        {
            retStr = makeErrorStr(str, len, retlen);
            return (retStr);
        }
        else
        {
            return (NULL);
        }
        break;
    }

    return (NULL);
}

/*********************************************************
 * makeGenericStr(char *, unsigned int, unsigned int *,  *
 *                char)                                  *
 *                                                       *
 * this function is used for (F) fatal error, (X) error, *
 * (W) warning, and (I) information strings.             *
 *                                                       *
 * The function returns "C\ [string]\r\n" where C is the *
 * above mentioned value. The entire string is returned  *
 * as more is better than less for these codes.          *
 ********************************************************/
char *makeGenericStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen,
    char c)
{
    /*
     * WARNING - have not included parsing of strings to include escaping of
     * CR or LF to '\013' and '\010' 
     */

    char *retStr,
       *copiedStr;
    unsigned int holdLen;
    int ret;

    // TODO: is len useful? can it be substituted for strlen(str) below?
    (void)len;

    if (!str)
        return NULL;

    copiedStr = strdup(str);
    if (!copiedStr)
        return NULL;

    holdLen = strlen(str) + 5;
    retStr = (char *)calloc(holdLen, 1);
    if (!retStr)
    {
        free(copiedStr);
        return NULL;
    }

    strip(copiedStr, WHITESPACE);
    ret = snprintf(retStr, holdLen, "%c %s\r\n", c, copiedStr);
    if (retlen)
        *retlen = ret;

    free(copiedStr);
    return retStr;
}

char *makeWarningStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    char *retStr;

    retStr = makeGenericStr(str, len, retlen, 'W');
    if (retStr)
        return (retStr);
    else
        return (NULL);

}


char *makeInfoStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    char *retStr;

    retStr = makeGenericStr(str, len, retlen, 'I');
    if (retStr)
        return (retStr);
    else
        return (NULL);

}

char *makeFatalStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    char *retStr;

    retStr = makeGenericStr(str, len, retlen, 'F');
    if (retStr)
        return (retStr);
    else
        return (NULL);

}

char *makeErrorStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    char *retStr;

    retStr = makeGenericStr(str, len, retlen, 'X');
    if (retStr)
        return (retStr);
    else
        return (NULL);

}

static char *makeAURStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen,
    char c)
{

    /*
     * the update string will contain "\010" and "\013" as replacements for
     * any in-line NL and CR values. Additionally, we need to preface the
     * message with "U " and suffix it with "\r\n". We do NOT include the 9 or 
     * 11 character %i format string.
     * 
     * Thus, the output string is: "U path_and_filename\r\n" (replace "U" with 
     * "A" or "R" depending on update/add/remove)
     * 
     * STRIKE THE ABOVE - we're using fgets() as the initial input from the
     * log file - and so HOW WOULD WE COME ACROSS AN EMBEDDED \n?!?!
     * 
     * The solution:
     * 
     * This function assumes that at the very least that the checks for
     * has_I_Format and has_Text_Value have passed succesfully. Further that
     * since this is an UPDATE string that the log line has the proper
     * extension {der,cer,pem,crl,roa}. Though we still try to make sure that 
     * the input string is at least 11 characters in length at the beginning
     * of the function.
     * 
     * As the output from this is not expected to be handled by the shell (it
     * is envisioned that {f}open(), etc. are used) we don't need to worry
     * about escaping shell nasties such as *;'` etc. etc.
     * 
     */

    int ret,
        holdLen;
    char *retStr,
       *ptr,
       *copiedStr;

    /*
     * sanity check 
     */
    if (!str || len < 11)
        return (NULL);

    /*
     * make local copy of 'len' bytes of str, null-terminated 
     */
    copiedStr = (char *)malloc(len + 1);
    if (!copiedStr)
        return NULL;
    strncpy(copiedStr, str, len);
    copiedStr[len] = '\0';

    /*
     * strip any pesky whitespaces that we will be clobbering anyway 
     */
    strip(copiedStr, WHITESPACE);

    /*
     * our return string will be the string passed in minus the 9 or 11 chars
     * in the %i description at the end plus 2 for "U " plus 3 for "\r\n\0" at 
     * the end 
     */
    ptr = start_of_next_field(copiedStr, WHITESPACE);
    holdLen = field_length(ptr, WHITESPACE) + 2 + 3;
    retStr = (char *)malloc(holdLen);
    if (!retStr)
    {
        free(copiedStr);
        return NULL;
    }

    ret = snprintf(retStr, holdLen, "%c %s\r\n", c, ptr);
    if (ret < 0 || ret >= holdLen)
    {                           /* error or overflow */
        free(retStr);
        free(copiedStr);
        return NULL;
    }
    if (retlen)
        *retlen = strlen(retStr);

    free(copiedStr);
    return retStr;
}


char *makeUpdateStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    return makeAURStr(str, len, retlen, 'U');
}


char *makeAddStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    return makeAURStr(str, len, retlen, 'A');
}


char *makeLinkStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    UNREFERENCED_PARAMETER(str);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(retlen);
    /*
     * this requires more than just makeGenericStr() 
     */
    /*
     * STUB 
     */
    return (NULL);
}

/*
 * Input string:  *deleting path/to/file.ext
 * Output string: R path/to/file.ext
 */
char *makeRemoveStr(
    const char *str,
    unsigned int len,
    unsigned int *retlen)
{
    return makeAURStr(str, len, retlen, 'R');
}

int looksOK(
    const char *str,
    unsigned int len)
{
    int c,
        i;

    c = i = 0;

    /*
     * start with simple sanity checks - minumum length, ascii characters,
     * etc. etc. Then move on to more message specific checks. 
     */

    /*
     * we expect even in the smallest log message that there will be two
     * characters. This would end up being a message from a delete '*\
     * [sometext]'. 
     */
    if (len < 2)
        return (FALSE);

    /*
     * PATH_MAX is the longest absolute path with filename allowed on most
     * systems. For Linux it is 4096. We also have at MOST 9 flags in the
     * rsync %i format which will be followed by a SPACE 
     */

    if (len > (PATH_MAX + 10))
        return (FALSE);

    /*
     * test for a newline 
     */
    if (!has_newline(str, len))
        return (FALSE);

    /*
     * we expect the entire string to be either printable chars or cr|nl 
     */
    for (i = 0; i < (int)len; i++)
    {
        c = (char)*(str + i);
        if (!(isprint((int)(unsigned char)c)) && ((c != 0x0d) && (c != 0x0a)))
            return (FALSE);
    }

    c = (unsigned char)*str;

    switch (c)
    {
    case '*':
        if (strncmp("*deleting ", str, strlen("*deleting ")) != 0)
            return (FALSE);
        if (len < 11)
            return (FALSE);
        if (!has_Correct_Extension(str, len))
            return (FALSE);
        break;
    case '<':
        if (!has_I_Format(str, len))
            return (FALSE);
        if (!has_Text_Value(str, len))
            return (FALSE);
        break;
    case '>':                  /* need to put in checks for {sym,hard}link
                                 * stuff */
        if (!has_I_Format(str, len))
            return (FALSE);
        if (!has_Text_Value(str, len))
            return (FALSE);
        if (!has_Correct_Extension(str, len))
            return (FALSE);
        break;
    case 'c':
        if (!has_I_Format(str, len))
            return (FALSE);
        if (!has_Text_Value(str, len))
            return (FALSE);
        break;
    case 'h':                  /* need to see what the data of this actually
                                 * ends up being */
        if (!has_I_Format(str, len))
            return (FALSE);
        if (!has_Text_Value(str, len))
            return (FALSE);
        break;
    case '.':
        if (!has_I_Format(str, len))
            return (FALSE);
        if (!has_Text_Value(str, len))
            return (FALSE);
        break;
    default:
        return (FALSE);
        break;
    }

    return (TRUE);
}

/************************************************
 * int has_newline(char *, unsigned int)        *
 *   a very trivial function that returns TRUE  *
 *   if there is a \n in the string and FALSE   *
 *   otherwise.                                 *
 *                                              *
 * Since we are ultimately reading in the str   *
 * from fgets() we are really only worried about*
 * situations where the buffer length was       *
 * exceeded.                                    *
 ************************************************/
int has_newline(
    const char *str,
    unsigned int len)
{
    const char *nl = NULL;

    UNREFERENCED_PARAMETER(len);
    nl = strrchr(str, '\n');
    if (nl)
    {
        return (TRUE);
    }
    else
    {
        return (FALSE);
    }
}

int has_I_Format(
    const char *str,
    unsigned int len)
{
    /*
     * This will check that the first 9 chars appear to be from the %i format. 
     * Note that in newer versions of rsync, the %i format has 11 chars.  The
     * following code should return true for both. 
     */

    int i,
        c,
        Y,
        X;

    if (len < 11)               /* YXcstpogz\ [file... */
        return (FALSE);

    Y = (char)*(str);
    X = (char)*(str + 1);

    switch (Y)
    {
    case '<':
    case '>':
    case 'c':
    case 'h':
    case '.':
        break;
    default:
        return (FALSE);
        break;
    }

    switch (X)
    {
    case 'f':
    case 'd':
    case 'L':
    case 'D':
    case 'S':
        break;
    default:
        return (FALSE);
        break;
    }

    for (i = 0; i <= 8; i++)
    {
        c = (char)*(str + i);
        if ((!isprint((int)(unsigned char)c)) || c == 0x20)
            return (FALSE);
    }

    return (TRUE);
}

int has_Text_Value(
    const char *str,
    unsigned int len)
{
    /*
     * checks to make sure there is some data after the %i format, we would
     * expect this to be a filename most of the time 
     */
    int i,
        pos,
        field_len;
    const char *text;

    if (len < 11 || strlen(str) < 11)
        return (FALSE);

    text = start_of_next_field(str, WHITESPACE);
    if (!text)
        return (FALSE);

    /*
     * Check that filename starts at 11th or 13th character.  Since the number 
     * depends on version of rsync; we allow either. 
     */
    pos = text - str;
    if (pos != 10 && pos != 12)
        return (FALSE);

    /*
     * the filename chars should be at the very least printable 
     */
    field_len = field_length(text, WHITESPACE);
    for (i = 0; i < field_len; i++)
        if (!isprint((int)(unsigned char)text[i]))
            return (FALSE);

    return (TRUE);
}

int has_Correct_Extension(
    const char *str,
    unsigned int len)
{
    const char *ptr;
    char hold[32];
    unsigned int endlen;

    UNREFERENCED_PARAMETER(len);
    memset(hold, '\0', sizeof(hold));

    for (ptr = str; *ptr >= ' '; ptr++);

    ptr = strrchr(str, '.');

    if (!ptr)
        return (FALSE);

    ptr++;
    if ((*ptr == '\0') || (*ptr == '\n') || (*ptr == 0x0d))
        return (FALSE);

    strncpy(hold, ptr, sizeof(hold) - 1);

    endlen = strlen(hold);

    /*
     * 4 with \n 
     */
    if ((endlen == 4) || (endlen == 3))
    {

        if (endlen == 4)
        {
            if (hold[endlen - 1] != '\n')
                return (FALSE);
        }

        if (strncasecmp(hold, "cer", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "pem", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "der", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "crl", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "gbr", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "roa", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "man", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "mft", 3) == 0)
            return (TRUE);

        if (strncasecmp(hold, "mnf", 3) == 0)
            return (TRUE);
    }

    return (FALSE);
}

char *makeStartStr(
    unsigned int *retlen)
{
    time_t seconds;
    char *time_str,
       *out_str;

    seconds = time(NULL);

    time_str = ctime(&seconds);

    out_str = (char *)malloc(strlen(time_str) + 4);
    if (!out_str)
        return (NULL);

    snprintf(out_str, 3, "B "); /* auto tack of \0 */

    strncat(out_str, time_str, strlen(time_str));

    *(char *)(out_str + ((strlen(out_str) - 1))) = '\0';

    strncat(out_str, "\r\n", 2);
    *retlen = (strlen(out_str));
    return (out_str);
}

char *makeEndStr(
    unsigned int *retlen)
{
    time_t seconds;
    char *time_str,
       *out_str;

    seconds = time(NULL);

    time_str = ctime(&seconds);

    out_str = (char *)malloc(strlen(time_str) + 4);
    if (!out_str)
        return (NULL);

    snprintf(out_str, 3, "E "); /* auto tack of \0 */

    strncat(out_str, time_str, strlen(time_str));

    *(char *)(out_str + ((strlen(out_str) - 1))) = '\0';

    strncat(out_str, "\r\n", 2);
    *retlen = (strlen(out_str));
    return (out_str);
}


/***************** Lower level parsing utilities. *****************/


/*
 * Detect the end of the current "directory block" in the rsync log file.
 * Returns the file position indicator via ftell() for the beginning of the
 * *next* directory block, or end-of-file.  The file position indicator is
 * restored to the current value at the end of this function.
 * 
 * Returns -1 on error.
 * 
 * Sample file:
 * 
 * *deleting SPARTA/1/C3A60F37CFC8876F19337BAAC87279C1B53DC38F.cer *deleting
 * SPARTA/SPARTA-ELS/2/0BFBDDC896073CA14265D5C50C04857A680F23F8.cer
 * .d..t...... SPARTA/1/ >f..t...... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.crl
 * >f..t...... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.mnf .d..t......
 * SPARTA/SPARTA-ELS/2/ >f..t......
 * SPARTA/SPARTA-ELS/2/0vSi6U4ZC_yKRITgmwzqC3Tq1H8.crl >f..t......
 * SPARTA/SPARTA-ELS/2/0vSi6U4ZC_yKRITgmwzqC3Tq1H8.mnf .d..t...... isc/2/
 * >f..t...... isc/2/r-Vxn-I7YluASnxRHksRELhf_Qk.crl >f..t......
 * isc/2/r-Vxn-I7YluASnxRHksRELhf_Qk.mnf .d..t...... isc/3/ >f..t......
 * isc/3/i8T5t-AgIfdC-yr_BzVVcm_7kT0.crl >f..t......
 * isc/3/i8T5t-AgIfdC-yr_BzVVcm_7kT0.mnf
 * 
 * An example of a "directory block" would be:
 * 
 * .d..t...... SPARTA/1/ >f..t...... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.crl
 * >f..t...... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.mnf
 * 
 */
long next_dirblock(
    FILE * fp)
{
    long initial_pos;
    long line_start_pos;
    char first_directory[PATH_MAX];
    int first_line;             /* boolean */
    const char *delimiters = " \n\r\t";

    if (!fp)
        return -1;

    initial_pos = ftell(fp);

    /*
     * Search line by line for a change in directory. 
     */
    first_line = 1;
    first_directory[0] = '\0';
    line_start_pos = -1;
    do
    {
        char line[PATH_MAX + 40];
        char fullpath[PATH_MAX];
        char directory[PATH_MAX];
        char *fullpath_start;

        line_start_pos = ftell(fp);
        if (!fgets(line, PATH_MAX + 40, fp))
            break;              /* Stop searching; it's the end of file. */

        if (!exists_non_delimiter(line, delimiters))
            continue;           /* Skip blank lines. */

        fullpath_start = start_of_next_field(line, delimiters);
        if (!fullpath_start)
        {
            line_start_pos = -1;        /* error code */
            LOG(LOG_ERR, "Malformed rsync log file line: %s", line);
            break;
        }

        if (!this_field(fullpath, PATH_MAX, fullpath_start, delimiters))
        {
            line_start_pos = -1;        /* error code */
            LOG(LOG_ERR, "Insufficient buffer to hold path: %s",
                    fullpath_start);
            break;
        }

        if (!dirname(directory, PATH_MAX, fullpath))
        {
            line_start_pos = -1;        /* error code */
            LOG(LOG_ERR,
                    "Insufficient buffer to hold directory.  Path = %s\n",
                    fullpath);
            break;
        }

        if (first_line)
        {
            /*
             * The following is safe despite strncpy weakness.  By this point, 
             * 'directory' will be safely NULL-terminated, and
             * 'first_directory' and 'directory' are equal sized buffers. 
             */
            strncpy(first_directory, directory, PATH_MAX);
            first_line = 0;
        }

        if (strncmp(first_directory, directory, PATH_MAX) != 0)
            break;              /* Stop searching; new directory found. */

    } while (1);

    fseek(fp, initial_pos, SEEK_SET);
    return line_start_pos;
}


int is_manifest(
    const char *path)
{
    if (!path)
        return 0;

    if (endswith(path, ".man") ||
        endswith(path, ".mnf") || endswith(path, ".mft"))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
