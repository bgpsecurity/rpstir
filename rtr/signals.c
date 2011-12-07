#include <signal.h>

#include "logging.h"

#include "signals.h"

static const int signals[] = {SIGHUP, SIGINT, SIGTERM};
#define NUM_SIGNALS (sizeof(signals) / sizeof(int))

static void initialize_sigset(sigset_t * set)
{
	size_t i;

	sigemptyset(set);
	for (i = 0; i < NUM_SIGNALS; ++i)
		sigaddset(set, signals[i]);
}

void handle_signals(void (*handler)(int))
{
	size_t i;
	struct sigaction action;

	action.sa_handler = handler;
	initialize_sigset(&action.sa_mask);
	action.sa_flags = 0;

	for (i = 0; i < NUM_SIGNALS; ++i)
		sigaction(signals[i], &action, NULL);
}

static void block_unblock_signals(bool block)
{
	int retval;
	sigset_t set;

	initialize_sigset(&set);

	retval = pthread_sigmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL);
	if (retval != 0)
	{
		LOG(LOG_WARNING, "can't %s signals (error code %d)",
			block ? "block" : "unblock",
			retval);
	}
}

void block_signals()
{
	block_unblock_signals(true);
}

void unblock_signals()
{
	block_unblock_signals(false);
}
