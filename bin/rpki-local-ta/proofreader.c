
#include <errno.h>
#include "rpki/rpwork.h"
#include "config/config.h"
#include "util/logging.h"

int warnings;

extern char errbuf[160];

#define warn(format, ...) \
    do { \
        LOG(LOG_WARNING, format, ## __VA_ARGS__); \
        warnings++; \
    } while (false)

#define fatal(format, ...) \
    do { \
        LOG(LOG_ERR, format, ## __VA_ARGS__); \
        if (warnings > 0) \
        { \
            LOG(LOG_ERR, "Had %d warnings. New file NOT created", warnings); \
        } \
        config_unload(); \
        CLOSE_LOG(); \
        exit(0); \
    } while (false)


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
            warn("Invalid line: %s", locbuf);
            numranges--;        // scrub the entry
        }
        else if (numranges > 0 /* haven't incremented it yet */  &&
                 overlap(&iprangesp[numranges - 1], &iprangesp[numranges]))
            warn("overlap at: %s", locbuf);
        tiprangep->text = (char *)calloc(1, strlen(locbuf) + 2);
        strcpy(tiprangep->text, locbuf);
        // get the next one
        if (!fgets(locbuf, sizeof(locbuf), str))
        {
            if (strcmp(ending, "SKI "))
                fatal("Premature end of file");
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
        fatal("Usage: name of constraints file");
    FILE *str = fopen(argv[1], "r");
    if (!str)
        fatal("Can't open %s", argv[1]);
    FILE *tmpstr;
    char *f = "xproof.tmp";
    int ansr,
        i = 0;
    struct keyring keyring = { NULL, NULL, NULL };

    OPEN_LOG("proofreader", LOG_USER);

    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't load configuration");
        exit(EXIT_FAILURE);
    }

    if (!(tmpstr = fopen(f, "w+")))
        fatal("Can't open %s", f);

    if ((ansr = parse_SKI_blocks(&keyring, str, argv[1], inbuf, sizeof(inbuf), &i)) < 0)
        fatal("Invalid line: %s", errbuf);
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
            fatal("Invalid line: %s", inbuf);
        while (*c == ' ' || *c == '\t')
            c++;
        if (*c != '\n')
            fatal("Invalid line: %s", inbuf);
        if (numskis)
        {
            int num;
            for (num = 0; num < numskis && strcmp(inbuf, skis[num]); num++);
            if (num < numskis)
                fatal("Duplicate SKI: %s ", &inbuf[4]);
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
            fatal("Premature end of file");
        if (strcmp(inbuf, "IPv4\n"))
            fatal("Missing IPv4 line");
        fputs(inbuf, tmpstr);   // print v4 hdr
        // get first v4 line, if any
        if (!fgets(inbuf, sizeof(inbuf), str))
            fatal("Premature end of file");
        // process v4 entries, if any
        process_type(str, tmpstr, 4, inbuf, "IPv6\n");
        fputs(inbuf, tmpstr);   // print v6 hdr
        // get first v6 line, if any
        if (!fgets(inbuf, sizeof(inbuf), str))
            fatal("Premature end of file");
        process_type(str, tmpstr, 6, inbuf, "AS#\n");
        fputs(inbuf, tmpstr);   // print as# hdr
        // get first AS#, if any
        if (!(c = fgets(inbuf, sizeof(inbuf), str)))
            break;
        process_type(str, tmpstr, 8, inbuf, "SKI ");
    }
    while (*inbuf);
    if (warnings == 0)
    {
        LOG(LOG_INFO, "Finished %s OK", argv[1]);
    }
    else
    {
        LOG(LOG_ERR, "Had %d warnings. New file NOT created", warnings);
    }
    config_unload();
    CLOSE_LOG();
    return 0;
}
