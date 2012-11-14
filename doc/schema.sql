-- NOTE: all the tables begin with 'rpstir_'. This prefix may be configurable.

-- NOTE: unless otherwise specified, all hash columns of type binary(32) are the sha256 of the entire file

-- NOTE: CMS objects are stored with the same hash in both rpstir_rpki_cert and their respective type's table (e.g. rpstir_rpki_manifest)

-- TODO: check KEYs

-- database-level metadata
-- current version: SELECT schema_version FROM rpstir_metadata ORDER BY installed DESC LIMIT 1;
-- on initializing or upgrading the schema to version foo: INSERT INTO rpstir_metadata (schema_version) VALUES (foo);
CREATE TABLE rpstir_metadata (
  schema_version int unsigned DEFAULT NULL, -- NULL indicates a development version with no version number
  installed timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (installed)
);


-- state shared by all objects with the same file contents and file type
CREATE TABLE rpstir_rpki_object (
  hash binary(32) NOT NULL,

  file_type ENUM('cer', 'crl', 'roa', 'mft', 'gbr') NOT NULL,

  -- 0: can't be parsed
  -- 1: parses, but fails single-file validity checks
  -- 2: passes single-file validity checks
  status tinyint unsigned NOT NULL DEFAULT 0,

  -- an error code, if appropriate
  -- this is a foreign key to rpstir_rpki_object_status.id
  status_reason int unsigned DEFAULT NULL,

  -- extra information about the status, if applicable given the value of status_reason
  status_explanation text DEFAULT NULL,

  PRIMARY KEY (hash, file_type),

  CHECK (status_explanation IS NULL OR status_reason IS NOT NULL)
);

-- information for a status code
-- (see rpstir_rpki_object.status_reason and rpstir_rpki_object.status_explanation)
CREATE TABLE rpstir_rpki_object_status (
  id int unsigned NOT NULL,

  -- what the status code indicates
  message text NOT NULL,

  -- a description of the format of the contents of rpstir_rpki_object.status_explanation
  explanation_contents text DEFAULT NULL,

  PRIMARY KEY (id)
);

-- state of a single attempt to download from a URI.  Note that the URI may represent a directory with multiple files and subdirectories.
CREATE TABLE rpstir_rpki_download (
  id bigint unsigned NOT NULL AUTO_INCREMENT,

  uri varchar(1023) NOT NULL, -- root of download URI, in normalized form

  start_time datetime NOT NULL,
  duration int unsigned NOT NULL, -- in seconds

  -- Example values and their meanings/examples:
  -- SUCCESS
  -- REMOTE_FAIL: network error, protocol error, remote side closed connection, etc.
  -- LOCAL_FAIL: out of disk space, system shutting down, etc.
  -- TIMEOUT: transfer took too long
  -- TOOBIG: remote side offered up too much data
  status tinyint unsigned NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY (uri, start_time),
  KEY (start_time)
);

-- state of a single object at a single URI from a single download (i.e. point in time)
-- rollback must guarantee that the active set of any single publication point will have the same download_id
CREATE TABLE rpstir_rpki_object_instance (
  -- where the file was downloaded from, in normalized form
  -- this should be a sub-path of or equal to (SELECT uri FROM rpstir_rpki_download WHERE id = download_id)
  uri varchar(1023) NOT NULL,
  download_id bigint unsigned NOT NULL,

  hash binary(32) NOT NULL,

  file_type ENUM('cer', 'crl', 'roa', 'mft') DEFAULT NULL, -- NULL indicates unrecognized

  PRIMARY KEY (uri, download_id),
  KEY object (hash, file_type),
  KEY download (download_id)
);

-- list of hashes to never use:
--   * Don't download from their URIs.
--   * Don't consider them valid for any purposes.
--   * TODO: more things not to use them for?
CREATE TABLE rpstir_rpki_blacklist (
  hash binary(32) NOT NULL,
  explanation text DEFAULT NULL,
  PRIMARY KEY (hash)
);

-- map internal hash to any other hash algs used in e.g. manifests
-- This should make algorithm agility somewhat more feasible in the future.
CREATE TABLE rpstir_rpki_hash (
  hash binary(32) NOT NULL, -- hash used throughout the schema
  alg ENUM('sha256') NOT NULL, -- alternate hash algorithm
  data varbinary(512) NOT NULL, -- alternate hash

  -- NOTE: these keys assume there are no hash collisions for any algorithm
  PRIMARY KEY (hash, alg), -- lookup an alternate hash based on local hash
  UNIQUE KEY (alg, data) -- lookup a local hash based on alternate hash
);

CREATE TABLE rpstir_uri_normalize (
  uri varchar(1023) NOT NULL, -- not normalized
  normalized varchar(1023) NOT NULL,
  PRIMARY KEY (uri),
  KEY (normalized)
);

-- Unlike other objects, TALs are not included in the rpstir_rpki_object
-- or rpstir_rpki_object_instance tables.
CREATE TABLE rpstir_rpki_tal (
  hash binary(32) NOT NULL,
  uri varchar(1023) NOT NULL, -- not normalized, direct from first line of TAL
  organization ENUM('IANA', 'RIR') DEFAULT NULL, -- NULL means other
  PRIMARY KEY (hash)
);

-- Certs should only be added to this table if they were downloaded from the appropriate URI
-- and have a matching public key.
CREATE TABLE rpstir_rpki_tal_certs (
  tal binary(32) NOT NULL, -- hash of TAL
  cert binary(32) NOT NULL, -- hash of cert
  latest boolean NOT NULL DEFAULT TRUE, -- only true for the latest valid cert for each TAL
  PRIMARY KEY (tal, cert)
);

CREATE TABLE rpstir_rpki_cert_asn (
  hash binary(32) NOT NULL,
  first_asn int unsigned NOT NULL,
  last_asn int unsigned NOT NULL,
  PRIMARY KEY (hash, first_asn),
  CHECK (first_asn <= last_asn)
);

CREATE TABLE rpstir_rpki_cert_ip (
  hash binary(32) NOT NULL,
  first_ip varbinary(16) NOT NULL, -- binary encoding, network byte order
  last_ip varbinary(16) NOT NULL, -- ditto
  PRIMARY KEY (hash, first_ip),
  CHECK (length(first_ip) = 4 OR length(first_ip) = 16),
  CHECK (length(first_ip) = length(last_ip)),
  CHECK (first_ip <= last_ip)
);

CREATE TABLE rpstir_rpki_cert_aia (
  hash binary(32) NOT NULL,
  preference int unsigned NOT NULL, -- lower number is more preferred
  uri varchar(1023) NOT NULL, -- not normalized
  PRIMARY KEY (hash, preference)
);

CREATE TABLE rpstir_rpki_cert_sia (
  hash binary(32) NOT NULL,
  method ENUM('id-ad-caRepository', 'id-ad-rpkiManifest', 'id-ad-signedObject') NOT NULL, -- XXX: use real OIDs
  preference int unsigned NOT NULL, -- lower number is more preferred
  uri varchar(1023) NOT NULL, -- not normalized
  PRIMARY KEY (hash, method, preference)
);

CREATE TABLE rpstir_rpki_cert_crldp (
  hash binary(32) NOT NULL,
  uri varchar(1023) NOT NULL, -- not normalized
  PRIMARY KEY (hash, uri)
);

-- store issuer and subject names
-- NOTE: id equality should be equivalent to value equality and SQL can't handle that sort of constraint well.
--       This means that this table neads a read/write lock and the write lock must be held before checking if
--       a name is present before adding it to the table.
CREATE TABLE rpstir_rpki_cert_name (
  id bigint unsigned NOT NULL AUTO_INCREMENT,

  -- 0-based index of the RelativeDistinguishedName SET
  sequence_index smallint unsigned NOT NULL,

  -- TODO: better OID type? ENUM maybe?
  attr_type varchar(64) NOT NULL,

  -- TODO: check type and length
  attr_value varbinary(256) NOT NULL,

  -- there is no PRIMARY KEY because each RelativeDistinguishedName is a SET

  -- lookup the values in order given an id
  KEY id (id, sequence_index),

  -- lookup an id given the values in order
  KEY value (sequence_index, attr_type, attr_value)
);

CREATE TABLE rpstir_rpki_cert_eku (
  hash binary(32) NOT NULL,

  -- index within sequence of KeyPurposeId
  idx bigint unsigned NOT NULL,

  -- TODO: better OID type?
  purpose varchar(64) NOT NULL,

  PRIMARY KEY (hash, idx),
  KEY (hash, purpose)
);

CREATE TABLE rpstir_rpki_cert (
  hash binary(32) NOT NULL,
  subject bigint unsigned NOT NULL, -- references 1 or more rows in rpstir_rpki_cert_name
  issuer bigint unsigned NOT NULL, -- ditto
  sn varbinary(20) NOT NULL,
  ski binary(20) NOT NULL,
  aki binary(20) DEFAULT NULL,
  valfrom datetime NOT NULL,
  valto datetime NOT NULL,
  inherit_asn boolean NOT NULL DEFAULT FALSE,
  inherit_ip boolean NOT NULL DEFAULT FALSE,
  PRIMARY KEY (hash),
  KEY ski (ski, subject),
  KEY aki (aki, issuer),
  KEY sig (sig),
  KEY isn (issuer, sn)
);

-- NOTE: Extra care may need to be taken to avoid inserting loops.
-- NOTE: notBefore- and notAfter-related flags in this table don't have to be set if the time is within a grace period
-- TODO: handle revoked certs
-- TODO: handle manifest issues
CREATE TABLE rpstir_rpki_cert_path (
  -- hash of parent. This can be equal to the hash of the child for TA certs.
  parent binary(32) NOT NULL,

  -- hash of child
  child binary(32) NOT NULL,

  -- bit set, 0 = valid path step from child to parent, flags could include:
  -- invalid-signature: child not correctly signed by parent
  -- invalid-rfc3779: child has AS or IP resources that parent doesn't (this can only happen if parent does not have inherit set for that resource)
  -- expired-parent: parent is expired
  -- notyet-parent: parent's notBefore date is in the future
  step_status bigint unsigned NOT NULL,

  -- bit set, 0 = there exists a valid path from child to parent to TA, flags are as above, with slight changes
  -- invalid-signature: there's no valid signature chain to TA
  -- invalid-rfc3779: there's no valid RFC 3779 chain to TA that follows a valid signature chain (this chain can include certs with inherit set)
  -- badtime-parent (= expired-parent & notyet-parent): there's no valid RFC 3779 + signature chain to TA that doesn't include expired or notyet certs
  path_status bigint unsigned NOT NULL,

  PRIMARY KEY (parent, child),
  KEY (child, path_status),

  CHECK (step_status = step_status & path_status)
);

CREATE TABLE rpstir_rpki_crl_sn (
  hash binary(32) NOT NULL,
  serial varbinary(20) NOT NULL,
  revocation_date datetime NOT NULL,
  PRIMARY KEY (hash, serial)
);

CREATE TABLE rpstir_rpki_crl (
  hash binary(32) NOT NULL,
  issuer varchar(511) NOT NULL, -- TODO: wrong type? see rpstir_rpki_cert_name
  last_upd datetime NOT NULL,
  next_upd datetime NOT NULL,
  crlno int unsigned NOT NULL,
  aki binary(20) NOT NULL,
  PRIMARY KEY (hash),
  KEY issuer (issuer),
  KEY aki (aki)
);

CREATE TABLE rpstir_rpki_manifest_files (
  hash binary(32) NOT NULL,
  filename varchar(255) NOT NULL,
  file_hash varbinary(512) NOT NULL,
  PRIMARY KEY (hash, filename)
);

CREATE TABLE rpstir_rpki_manifest (
  hash binary(32) NOT NULL,
  manifest_number varbinary(20) NOT NULL,
  this_upd datetime NOT NULL,
  next_upd datetime NOT NULL,
  file_hash_alg ENUM('sha256') NOT NULL,
  PRIMARY KEY (hash),
);

CREATE TABLE rpstir_prefix (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  prefix varbinary(16) NOT NULL, -- binary encoding, network byte order, filled with 0s to the full length for the address family
  prefix_length tinyint unsigned NOT NULL,
  max_prefix_length tinyint unsigned NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY (prefix, prefix_length, max_prefix_length),
  CHECK (length(prefix) = 4 OR length(prefix) = 16),
  CHECK (prefix_length <= max_prefix_length),
  CHECK (max_prefix_length <= length(prefix) * 8)
);

CREATE TABLE rpstir_rpki_roa_prefix (
  hash binary(32) NOT NULL,
  prefix_id bigint unsigned NOT NULL,
  PRIMARY KEY (hash, prefix_id)
);

CREATE TABLE rpstir_rpki_roa (
  hash binary(32) NOT NULL,
  asn int unsigned NOT NULL,
  PRIMARY KEY (hash)
);

CREATE TABLE rpstir_rtr_full (
  serial_num int unsigned NOT NULL,
  asn int unsigned NOT NULL,
  prefix_id bigint unsigned NOT NULL
  PRIMARY KEY (serial_num, asn, prefix_id)
);

CREATE TABLE rpstir_rtr_incremental (
  serial_num int unsigned NOT NULL,
  is_announce boolean NOT NULL,
  asn int unsigned NOT NULL,
  prefix_id bigint unsigned NOT NULL,
  PRIMARY KEY (serial_num, asn, prefix_id)
);

CREATE TABLE rpstir_rtr_session (
  session_id smallint unsigned NOT NULL,
  PRIMARY KEY (session_id)
);

CREATE TABLE rpstir_rtr_update (
  serial_num int unsigned NOT NULL,
  prev_serial_num int unsigned DEFAULT NULL,
  create_time datetime NOT NULL,
  has_full boolean NOT NULL,
  PRIMARY KEY (serial_num),
  UNIQUE KEY prev_serial_num (prev_serial_num),
  KEY create_time (create_time)
);
