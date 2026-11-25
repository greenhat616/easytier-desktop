CREATE TABLE settings (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    payload BLOB NOT NULL
) STRICT;
INSERT INTO settings VALUES (1, CAST('{"allow_list":[],"selected_core":null}' AS BLOB));
CREATE TABLE removal_pending (
    id TEXT PRIMARY KEY
) STRICT;
CREATE TABLE spec_revisions (
    id TEXT PRIMARY KEY,
    revision TEXT NOT NULL
) STRICT;
-- V0 did not store per-config revisions. Anchor those legacy configs to
-- the snapshot revision; current commits record their exact revision.
INSERT INTO spec_revisions SELECT instances.id, meta.revision FROM instances, meta WHERE meta.singleton=1;
PRAGMA user_version = 1;
