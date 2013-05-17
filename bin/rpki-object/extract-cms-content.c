#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rpki-asn1/cms.h"


static void usage(
    int argc,
    char **argv)
{
    (void)argc;
    fprintf(stderr, "Usage: %s <file>\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Given a CMS file (e.g., a Ghostbusters record),\n");
    fprintf(stderr, "extract the content to standard output.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This is useful to get the vCard out of a Ghostbusters\n");
    fprintf(stderr, "record.\n");
}

/**
    Print the CMS file's encapsulated content to stdout.

    @return True on success, false on failure.
*/
static bool extract_content(
    const char * file)
{
    bool ret = false;

    struct CMSBlob cms;
    CMSBlob(&cms, 0);
    if (get_casn_file(&cms.self, file, 0) < 0)
    {
        fprintf(stderr, "Error reading CMS file: %s\n", file);
        goto done;
    }

    unsigned char *content;
    int content_len = readvsize_casn(
        &cms.content.signedData.encapContentInfo.eContent, &content);
    if (content_len < 0)
    {
        fprintf(stderr, "Error reading the CMS file's content.\n");
        goto done;
    }

    (void)write(STDOUT_FILENO, content, (size_t)content_len);

    ret = true;

done:

    delete_casn(&cms.self);

    return ret;
}

int main(
    int argc,
    char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Please specify exactly one file.\n");
        usage(argc, argv);
        return EXIT_FAILURE;
    }

    if (!extract_content(argv[1]))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
