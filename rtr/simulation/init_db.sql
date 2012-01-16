TRUNCATE TABLE rtr_session;
TRUNCATE TABLE rtr_update;
TRUNCATE TABLE rtr_full;
TRUNCATE TABLE rtr_incremental;

INSERT INTO rtr_session (session_id) VALUES (FLOOR(RAND() * (1 << 16)));
