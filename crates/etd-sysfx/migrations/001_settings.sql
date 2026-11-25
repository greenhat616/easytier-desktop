CREATE TABLE settings (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    payload BLOB NOT NULL
) STRICT;
INSERT INTO settings VALUES (1, CAST('{"allow_list":[],"selected_core":null}' AS BLOB));
CREATE TABLE removal_pending (
    id TEXT PRIMARY KEY
) STRICT;
PRAGMA user_version = 1;
