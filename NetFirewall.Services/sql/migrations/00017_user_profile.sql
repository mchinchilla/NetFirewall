-- 00017_user_profile.sql
-- Add profile fields to users. Kept on the users table (1:1 with the row,
-- always loaded together) instead of a separate user_profiles table to avoid
-- a JOIN on every auth check.

ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name   varchar(80);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name    varchar(80);
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name varchar(160);
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone        varchar(40);
ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone     varchar(64) DEFAULT 'UTC';
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale       varchar(16) DEFAULT 'en';
