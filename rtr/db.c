#include "db.h"

struct db_request_state {
	struct db_request request;
	struct db_query_progress progress;
};
