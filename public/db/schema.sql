-- users & identities
CREATE TABLE IF NOT EXISTS identities (
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,              -- 'twitch'
  provider_user_id TEXT NOT NULL,      -- Twitch user id
  display_name TEXT,
  avatar_url TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (provider, provider_user_id)
);

-- campaigns (current giveaway)
CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  starts_at INTEGER,
  ends_at INTEGER
);

-- points ledger (append-only)
CREATE TABLE IF NOT EXISTS points_ledger (
  event_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  points_delta INTEGER NOT NULL,
  reason TEXT,                         -- 'watch'|'bonus'|'manual'...
  trace_id TEXT,
  created_at INTEGER NOT NULL,
  metadata TEXT
);

-- tickets ledger (append-only)
CREATE TABLE IF NOT EXISTS tickets_ledger (
  event_id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  tickets_delta INTEGER NOT NULL,
  trace_id TEXT,
  created_at INTEGER NOT NULL,
  metadata TEXT
);
