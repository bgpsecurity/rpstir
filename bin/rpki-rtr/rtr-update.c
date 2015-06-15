/************************
 * Get the next round of RTR data into the database
 ***********************/

#include "util/logging.h"
#include "db/connect.h"
#include "db/clients/rtr.h"
#include "config/config.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <time.h>


int main(
    int argc,
    char **argv)
{
    int ret = EXIT_SUCCESS;
    bool done_db_init = false;
    bool done_db_thread_init = false;
    dbconn * db = NULL;

    bool first_time;
    bool force_update = false;
    bool update_had_changes;
    serial_number_t previous_serial;
    serial_number_t current_serial;

    if (argc < 1 || argc > 2)
    {
        fprintf(stderr,
                "Usage: %s [<next serial number>]\n",
                argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr,
                "The next serial number should only be specified in test mode.\n");
        return EXIT_FAILURE;
    }

    OPEN_LOG("rtr-update", LOG_USER);

    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't load configuration");
        return EXIT_FAILURE;
    }

    // initialize the database connection
    if (!db_init())
    {
        LOG(LOG_ERR, "Could not initialize database program.");
        ret = EXIT_FAILURE;
        goto done;
    }
    done_db_init = true;

    if (!db_thread_init())
    {
        LOG(LOG_ERR, "Could not initialize database thread.");
        ret = EXIT_FAILURE;
        goto done;
    }
    done_db_thread_init = true;

    db = db_connect_default(DB_CLIENT_RTR);
    if (db == NULL)
    {
        LOG(LOG_ERR,
            "Could not connect to the database, check your config "
            "file.");
        ret = EXIT_FAILURE;
        goto done;
    }


    if (!db_rtr_has_valid_session(db))
    {
        return EXIT_FAILURE;
    }

    // Get the previous serial number.
    switch (db_rtr_get_latest_sernum(db, &previous_serial))
    {
        case GET_SERNUM_SUCCESS:
            first_time = false;
            // previous_serial was set by db_rtr_get_latest_sernum
            break;

        case GET_SERNUM_NONE:
            first_time = true;
            // Set previous_serial to a pseudo-random number
            srandom((unsigned int)time(NULL));
            previous_serial = (serial_number_t)random();
            break;

        case GET_SERNUM_ERR:
        default:
            LOG(LOG_ERR, "Error finding latest serial number.");
            ret = EXIT_FAILURE;
            goto done;
    }

    if (!db_rtr_delete_incomplete_updates(db))
    {
        LOG(LOG_ERR, "Error deleting incomplete updates.");
        ret = EXIT_FAILURE;
        goto done;
    }

    // Get/compute the current serial number.
    if (argc > 1)
    {
        force_update = true;
        if (sscanf(argv[1], "%" SCNSERIAL, &current_serial) != 1)
        {
            fprintf(stderr,
                    "Error: next serial number must be a nonnegative integer\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        // NOTE: this relies on unsigned integer wrap-around to zero
        current_serial = previous_serial + 1;
    }

    // Make sure we're not about to overwrite current_serial, create a
    // loop, or start a diverging history, even though these should be
    // *really* unlikely.
    if (!first_time &&
        !db_rtr_good_serials(db, previous_serial, current_serial))
    {
        if (argc > 1)
        {
            LOG(LOG_ERR,
                "Error: rtr_update is full or in an unusual state, "
                "or the specified next serial number already "
                "exists.");
        }
        else
        {
            LOG(LOG_ERR,
                "Error: rtr_update table is either full or in an "
                "unusual state.");
        }

        ret = EXIT_FAILURE;
        goto done;
    }

    if (!db_rtr_insert_full(db, current_serial))
    {
        LOG(LOG_ERR, "Could not copy current RPKI state.");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (!first_time &&
        !db_rtr_insert_incremental(db, previous_serial, current_serial))
    {
        LOG(LOG_ERR, "Could not compute incremental changes.");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (first_time)
    {
        update_had_changes = true;
    }
    else
    {
        switch (db_rtr_has_incremental_changes(db, current_serial))
        {
            case 1:
                update_had_changes = true;
                break;

            case 0:
                update_had_changes = false;
                break;

            case -1:
            default:
                LOG(LOG_ERR,
                    "Error determining if there were any changes.");
                ret = EXIT_FAILURE;
                goto done;
        }
    }

    if (update_had_changes || force_update)
    {
        // Make the new serial number available for use.
        if (
            !db_rtr_insert_update(db, current_serial, previous_serial,
                first_time))
        {
            LOG(LOG_ERR, "Error making updates available.");
            ret = EXIT_FAILURE;
            goto done;
        }
    }
    else
    {
        LOG(LOG_INFO,
            "Data had no changes since the last update, so no update "
            "was made.");

        // The new data in rtr_full is useless, so delete it.
        if (!db_rtr_delete_full(db, current_serial))
        {
            LOG(LOG_ERR, "Error deleting duplicate data in rtr_full.");
            ret = EXIT_FAILURE;
            goto done;
        }

        // there's nothing to delete from rtr_incremental
    }

    // clean up all the data no longer needed
    // save last two full updates so that no problems at transition
    // (with client still receiving data from previous one)
    // 
    // NOTE: The order of these updates and deletes is important.
    // All data must be marked as unusable according to rtr_update
    // before it is deleted from rtr_full or rtr_incremental.
    if (
        !db_rtr_ignore_old_full(
            db, current_serial, previous_serial) ||
        !db_rtr_delete_old_full(
            db, current_serial, previous_serial) ||
        !db_rtr_delete_old_update(
            db, current_serial, previous_serial) ||
        !db_rtr_ignore_old_incremental(db) ||
        !db_rtr_delete_old_incremental(db) ||
        false)
    {
        LOG(LOG_ERR, "Error cleaning up old data.");
        ret = EXIT_FAILURE;
        goto done;
    }


done:

    if (db != NULL)
    {
        db_disconnect(db);
    }

    if (done_db_thread_init)
    {
        db_thread_close();
    }

    if (done_db_init)
    {
        db_close();
    }

    config_unload();

    CLOSE_LOG();

    return ret;
}
