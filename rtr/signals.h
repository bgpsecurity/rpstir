#ifndef _RTR_SIGNALS_H
#define _RTR_SIGNALS_H

void handle_signals(
    void (*handler) (int));

void block_signals(
    );
void unblock_signals(
    );

#endif
