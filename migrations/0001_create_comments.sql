-- Create comments table for unit (submission) detail pages
-- Notes:
-- - Soft delete via deleted_at/deleted_by (matches submissions pattern)
-- - created_at stored as ISO8601 text

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  body TEXT NOT NULL,
  author_name TEXT NOT NULL,
  author_email TEXT NOT NULL,
  created_at TEXT NOT NULL,
  deleted_at TEXT,
  deleted_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_comments_submission_created
  ON comments(submission_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_comments_submission
  ON comments(submission_id);
