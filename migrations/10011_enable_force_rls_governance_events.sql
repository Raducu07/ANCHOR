-- Ensure governance_events is protected by RLS (ENABLE + FORCE)

ALTER TABLE public.governance_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governance_events FORCE ROW LEVEL SECURITY;
