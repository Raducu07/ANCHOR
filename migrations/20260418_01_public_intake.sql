-- 20260418_01_public_intake.sql
-- Public commercial intake persistence (platform-scoped, not clinic RLS)

CREATE TABLE IF NOT EXISTS demo_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  full_name text NOT NULL,
  work_email text NOT NULL,
  clinic_name text NOT NULL,
  role text NOT NULL,
  current_ai_use text NOT NULL,
  primary_interest text NOT NULL,
  biggest_concern text NOT NULL,
  clinic_size text NULL,
  phone text NULL,
  message text NULL,
  consent boolean NOT NULL,
  source_page text NULL,
  utm_source text NULL,
  utm_medium text NULL,
  utm_campaign text NULL,
  status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','contacted','booked','qualified','closed')),
  notes text NULL
);

CREATE INDEX IF NOT EXISTS idx_demo_requests_created_at
  ON demo_requests (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_demo_requests_status_created_at
  ON demo_requests (status, created_at DESC);

CREATE TABLE IF NOT EXISTS start_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  clinic_name text NOT NULL,
  full_name text NOT NULL,
  work_email text NOT NULL,
  role text NOT NULL,
  preferred_plan text NOT NULL,
  clinic_size text NOT NULL,
  current_ai_use text NOT NULL,
  rollout_timing text NOT NULL,
  phone text NULL,
  site_count integer NULL CHECK (site_count IS NULL OR site_count >= 0),
  message text NULL,
  consent boolean NOT NULL,
  source_page text NULL,
  utm_source text NULL,
  utm_medium text NULL,
  utm_campaign text NULL,
  status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','contacted','onboarding','qualified','closed')),
  notes text NULL
);

CREATE INDEX IF NOT EXISTS idx_start_requests_created_at
  ON start_requests (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_start_requests_status_created_at
  ON start_requests (status, created_at DESC);

CREATE TABLE IF NOT EXISTS public_site_chat_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  session_id text NULL,
  question_text text NOT NULL CHECK (char_length(question_text) <= 500),
  question_text_redacted text NULL CHECK (question_text_redacted IS NULL OR char_length(question_text_redacted) <= 500),
  question_category text NULL,
  matched_topic text NULL,
  answer_confidence text NULL,
  suggested_cta text NULL,
  source_page text NULL,
  utm_source text NULL,
  utm_medium text NULL,
  utm_campaign text NULL,
  contains_email boolean NOT NULL DEFAULT false,
  contains_phone boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_public_site_chat_events_created_at
  ON public_site_chat_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_public_site_chat_events_category_created_at
  ON public_site_chat_events (question_category, created_at DESC);
