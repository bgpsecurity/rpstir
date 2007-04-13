#ifndef __SIG_HANDLER_H
#define __SIG_HANDLER_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "main.h"
#include "parse.h"

void sig_handler(int);
int setup_sig_catchers(void);


#endif
