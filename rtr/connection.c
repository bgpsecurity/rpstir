/*
Make sure that all resources are cleaned up by functions passed to pthread_cleanup_push, except for the resources that are given by the connection control thread.

Make sure that cleanup ensures no other threads (e.g. db threads) have access to the connection semaphore.

Make sure that cleanup cancels any DB requests.
*/
