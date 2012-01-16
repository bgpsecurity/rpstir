DELETE rtr_incremental
FROM rtr_incremental
LEFT JOIN rtr_update ON rtr_incremental.serial_num = rtr_update.serial_num
WHERE rtr_update.serial_num IS NULL;

DELETE rtr_full
FROM rtr_full
LEFT JOIN rtr_update ON rtr_full.serial_num = rtr_update.serial_num
WHERE rtr_update.serial_num IS NULL;

SET @session_id = (SELECT session_id FROM rtr_session);
SET @prev_ser = (SELECT serial_num FROM rtr_update ORDER BY create_time DESC LIMIT 1);
SET @ser = IF(@prev_set IS NULL,
	FLOOR(RAND(@session_id) * (1 << 32)),
	IF(@prev_ser >= (1 << 32) - 1, 0, @session_id + 1));

-- TODO: insert multiple rows
INSERT INTO rtr_full (serial_num, asn, ip_addr)
SELECT
	@ser,
	FLOOR(1 + RAND(@session_id * @ser + 1) * ((1 << 32) - 1)),
	IF(RAND(@session_id * @ser + 2) >= 0.5,
		CONCAT(
			FLOOR(RAND(@session_id * @ser + 3) * 256),
			'.',
			FLOOR(RAND(@session_id * @ser + 4) * 256),
			'.',
			FLOOR(RAND(@session_id * @ser + 5) * 256),
			'.',
			FLOOR(RAND(@session_id * @ser + 6) * 256),
			'/',
			@len := FLOOR(RAND(@session_id * @ser + 7) * 33),
			'(',
			@len + FLOOR(RAND(@session_id * @ser + 8) * (33 - @len)),
			')'),
		CONCAT(
			HEX(FLOOR(RAND(@session_id * @ser + 3) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 4) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 5) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 6) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 7) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 8) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 9) * (1 << 16))),
			':',
			HEX(FLOOR(RAND(@session_id * @ser + 10) * (1 << 16))),
			'/',
			@len := FLOOR(RAND(@session_id * @ser + 11) * 129),
			'(',
			@len + FLOOR(RAND(@session_id * @ser + 12) * (129 - @len)),
			')'));

INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)
SELECT @ser, 1, t1.asn, t1.ip_addr
FROM rtr_full AS t1
LEFT JOIN rtr_full AS t2 ON t2.serial_num = @prev_ser AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr
WHERE t1.serial_num = @ser AND t2.serial_num IS NULL;

INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)
SELECT @ser, 0, t1.asn, t1.ip_addr
FROM rtr_full AS t1
LEFT JOIN rtr_full AS t2 ON t2.serial_num = @ser AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr
WHERE t1.serial_num = @prev_ser AND t2.serial_num IS NULL;

INSERT INTO rtr_update VALUES (@ser, @prev_ser, now(), true);

UPDATE rtr_update SET has_full = false WHERE serial_num != @ser AND serial_num != @prev_ser;

DELETE FROM rtr_full WHERE serial_num != @ser AND serial_num != @prev_ser;

DELETE FROM rtr_update
WHERE create_time < adddate(now(), interval -24 hour)
AND serial_num != @ser AND serial_num != @prev_ser;

UPDATE rtr_update AS r1
LEFT JOIN rtr_update AS r2 ON r2.serial_num = r1.prev_serial_num
SET r1.prev_serial_num = NULL
WHERE r2.serial_num IS NULL;

DELETE rtr_incremental
FROM rtr_incremental
LEFT JOIN rtr_update ON rtr_incremental.serial_num = rtr_update.serial_num
WHERE rtr_update.prev_serial_num IS NULL;
