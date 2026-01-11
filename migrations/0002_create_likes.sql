-- Likes table
-- One like per (submission_id, user_email)

CREATE TABLE IF NOT EXISTS likes (
  submission_id TEXT NOT NULL,
  user_email    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  PRIMARY KEY (submission_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_likes_submission_id ON likes (submission_id);
CREATE INDEX IF NOT EXISTS idx_likes_user_email    ON likes (user_email);
