-- Version 0 baseline. The version 1 migration adds host settings.
CREATE TABLE meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    revision TEXT NOT NULL,
    next_effect TEXT NOT NULL
) STRICT;
INSERT INTO meta VALUES (1, '0', '0');
CREATE TABLE instances (
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL
) STRICT;
CREATE TABLE requests (
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL
) STRICT;
CREATE TABLE high_water (
    id TEXT PRIMARY KEY,
    epoch TEXT NOT NULL
) STRICT;
CREATE TABLE generations (
    instance TEXT NOT NULL,
    epoch TEXT NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (instance, epoch)
) STRICT;
CREATE TABLE effects (
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL
) STRICT;
