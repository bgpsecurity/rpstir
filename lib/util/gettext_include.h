//This .h file is to be used to include gettext headers and macros

#ifndef GETTEXT_INCLUDE
#define GETTEXT_INCLUDE

#include <locale.h>
#include <libintl.h>

#define _(String) gettext (String)

#endif
