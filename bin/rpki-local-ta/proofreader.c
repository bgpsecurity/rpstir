
#include <errno.h>
#include "rpki/rpwork.h"
#include "config/config.h"
#include "util/logging.h"
#include "util/logutils.h"

char *msgs[] = {
    "Finished %s OK\n",
    "Usage: name of constraints file",  // 1
    "Invalid line: %s",
    "Duplicate SKI: %s ",       // 3
    "Missing %s line\n",
    "Premature end of file\n",  // 5
    "overlap at: %s",
    "Can't open %s\n",          // 7
    "\nHad warnings.  New file NOT created\n",
};

int warnings;

extern char errbuf[160];

static void warn(
    int err,
    char *paramp)
{
    log_msg(LOG_WARNING, msgs[err], paramp);
    if (err)
        warnings++;
}

static void fatal(
    int err,
    char *paramp)
{
    warn(err, paramp);
    if (err)
        warn(8, "");
    log_close();
    exit(0);
}

static void process_type(
    FILE * str,
    FILE * tmpstr,
    int typ,
    char *inbuf,
    char *ending)
{
    int numranges;
    struct iprange *iprangesp = (struct iprange *)0;
    char locbuf[80];
    strcpy(locbuf, inbuf);
    for (numranges = 0; strncmp(locbuf, ending, strlen(ending)); numranges++)
    {
        if (!numranges)
            iprangesp = (struct iprange *)calloc(1, sizeof(struct iprange));
        else
            iprangesp = (struct iprange *)realloc(iprangesp,
                                                  (sizeof(struct iprange) *
                                                   (numranges + 1)));
        struct iprange *tiprangep = &iprangesp[numranges];
        if (txt2loc(typ, locbuf, tiprangep) < 0)
        {
            warn(2, locbuf);
            numranges--;        // scrub the entry
        }
        else if (numranges > 0 /* haven't incremented it yet */  &&
                 overlap(&iprangesp[numranges - 1], &iprangesp[numranges]))
            warn(6, locbuf);
        tiprangep->text = (char *)calloc(1, strlen(locbuf) + 2);
        strcpy(tiprangep->text, locbuf);
        // get the next one
        if (!fgets(locbuf, sizeof(locbuf), str))
        {
            if (strcmp(ending, "SKI "))
                fatal(5, "");
            else
            {
                *locbuf = (char)0;
                numranges++;    // have to count last one
                break;
            }
        }
    }
    strcpy(inbuf, locbuf);
    sort_resources(iprangesp, numranges);
    int i;
    for (i = 0; i < numranges; i++)
        fprintf(tmpstr, "%s", iprangesp[i].text);
    free(iprangesp);
}

int main(
    int argc,
    char **argv)
{
    char **skis,
        inbuf[128];
    int numskis = 0;
    if (argc < 2)
        fatal(1, (char *)0);
    FILE *str = fopen(argv[1], "r");
    if (!str)
        fatal(7, argv[1]);
    FILE *tmpstr;
    char *f = "xproof.tmp";
    int ansr,
        i = 0;
    struct keyring keyring = { NULL, NULL, NULL };

    if (log_init("proofreader.log", "proofreader", LOG_DEBUG, LOG_DEBUG) != 0)
    {
        perror("Failed to initialize proofreader log file");
        exit(1);
    }

    OPEN_LOG(PACKAGE_NAME "-proofreader", LOG_USER);

    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't load configuration");
        exit(EXIT_FAILURE);
    }

    if (!(tmpstr = fopen(f, "w+")))
        fatal(7, f);

    if ((ansr = parse_SKI_blocks(&keyring, str, inbuf, sizeof(inbuf), &i)) < 0)
        fatal(2, errbuf);
    fseek(str, (long)0, 0);
    *inbuf = 0;
    while (1)
    {
        fgets(inbuf, sizeof(inbuf), str);
        if (!strncmp(inbuf, "SKI ", 4))
            break;
        fputs(inbuf, tmpstr);
    }
    char *c;
    do                          // starting with first SKI line
    {
        for (c = &inbuf[4]; *c && ((*c >= '0' && *c <= '9') || *c == ':' ||
                                   (*c >= 'A' && *c <= 'F') || (*c >= 'a'
                                                                && *c <= 'f'));
             c++);
        if (c != &inbuf[63])
            fatal(2, inbuf);
        while (*c == ' ' || *c == '\t')
            c++;
        if (*c != '\n')
            fatal(2, inbuf);
        if (numskis)
        {
            int num;
            for (num = 0; num < numskis && strcmp(inbuf, skis[num]); num++);
            if (num < numskis)
                fatal(3, &inbuf[4]);
        }
        if (!numskis)
            skis = (char **)calloc(2, sizeof(char *));
        else
            skis = (char **)realloc(skis, (sizeof(char *) * (numskis + 2)));
        skis[numskis] = calloc(1, strlen(inbuf) + 2);
        strcpy(skis[numskis], inbuf);
        numskis++;
        fputs(inbuf, tmpstr);
        // get IPv4 start
        if (!fgets(inbuf, sizeof(inbuf), str))
            fatal(5, "");
        if (strcmp(inbuf, "IPv4\n"))
            fatal(4, "IPv4");
        fputs(inbuf, tmpstr);   // print v4 hdr
        // get first v4 line, if any
        if (!fgets(inbuf, sizeof(inbuf), str))
            fatal(5, "");
        // process v4 entries, if any
        process_type(str, tmpstr, 4, inbuf, "IPv6\n");
        fputs(inbuf, tmpstr);   // print v6 hdr
        // get first v6 line, if any
        if (!fgets(inbuf, sizeof(inbuf), str))
            fatal(5, "");
        process_type(str, tmpstr, 6, inbuf, "AS#\n");
        fputs(inbuf, tmpstr);   // print as# hdr
        // get first AS#, if any
        if (!(c = fgets(inbuf, sizeof(inbuf), str)))
            break;
        process_type(str, tmpstr, 8, inbuf, "SKI ");
    }
    while (*inbuf);
    if (warnings)
        fatal(8, "");
    fatal(0, argv[1]);
    config_unload();
    CLOSE_LOG();
    log_close();
    return 0;
}
