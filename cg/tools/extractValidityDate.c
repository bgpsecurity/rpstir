
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include "certificate.h"
#include "stringutils.h"

static void usage(
    int argc,
    char *argv[])
{
    fprintf(stderr,
            "Extracts a validity date (notBefore/notAfter) from a certificate "
            "and writes it to stdout.\n"
            "\n"
            "Usage: %s [options] <certificate_file>\n"
            "\n"
            "Options:\n"
            "    -b\tRetrieve notBefore (default is to extract both)\n"
            "    -a\tRetrieve notAfter\n"
            "    -g\tAlways print in GeneralizedTime format\n", argv[0]);
}

static int fprintDate(
    FILE * fp,
    struct CertificateValidityDate *date,
    int gtime)
{
    int date_len;               /* length of date string */
    char *date_str = NULL;      /* date string */
    int ret;

    if (!fp || !date)
    {
        fprintf(stderr, "Invalid input to fprintDate\n");
        return -1;
    }

    date_len = vsize_casn(&date->self);
    date_str = (char *)calloc(date_len + 2, 1);
    if (!date_str)
    {
        fprintf(stderr, "Memory allocation failure\n");
        return -1;
    }
    ret = read_casn(&date->self, (unsigned char *)date_str);
    if (ret < date_len)
    {
        fprintf(stderr, "Read failure: got %d, expected %d bytes\n", ret,
                date_len);
        return -2;
    }

    if (gtime && strlen(date_str) == 13)
    {                           /* UTCTime must be converted */
        char year_str[3];
        int year;
        /*
         * Interpret UTCTime according to
         * http://tools.ietf.org/html/rfc5280#section-4.1.2.5.1 
         */
        strncpy(year_str, date_str, 2);
        year_str[2] = '\0';
        year = atoi(year_str);
        if (year >= 50)
            fprintf(fp, "19%s\n", date_str);
        else
            fprintf(fp, "20%s\n", date_str);
    }
    else
    {                           /* GeneralizedTime already, or print either */
        fprintf(fp, "%s\n", date_str);
    }

    free(date_str);

    return 0;
}

int main(
    int argc,
    char *argv[])
{
    int c = 0;                  /* command line option character */
    int option_notbefore = 0;   /* retrieve notBefore date */
    int option_notafter = 0;    /* retrieve notAfter date */
    int option_gtime = 0;       /* force GeneralizedTime output */
    const char *file = NULL;    /* certificate file */
    struct Certificate cert;    /* ASN.1 certificate object */
    int ret;                    /* return value */

    /*
     * Parse command line arguments. 
     */
    opterr = 0;
    while ((c = getopt(argc, argv, "bag")) != -1)
    {
        switch (c)
        {
        case 'b':
            option_notbefore = 1;
            break;
        case 'a':
            option_notafter = 1;
            break;
        case 'g':
            option_gtime = 1;
            break;
        case '?':
            if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            usage(argc, argv);
            return -1;
        default:
            usage(argc, argv);
            return -1;
        }
    }
    /*
     * If no selection, default to both dates. 
     */
    if (option_notbefore == 0 && option_notafter == 0)
    {
        option_notbefore = 1;
        option_notafter = 1;
    }
    if (optind >= argc)
    {
        usage(argc, argv);
        return -1;
    }
    file = argv[optind];

    /*
     * Parse certificate. 
     */
    Certificate(&cert, (unsigned short)0);      /* constructor */
    ret = get_casn_file(&cert.self, (char *)file, 0);
    if (ret < 0)
    {
        fprintf(stderr, "Could not open file: %s\n", file);
        return -2;
    }

    /*
     * Extract dates 
     */
    if (option_notbefore)
        fprintDate(stdout, &cert.toBeSigned.validity.notBefore, option_gtime);
    if (option_notafter)
        fprintDate(stdout, &cert.toBeSigned.validity.notAfter, option_gtime);

    /*
     * Clean up. 
     */
    delete_casn(&cert.self);
    return 0;
}
