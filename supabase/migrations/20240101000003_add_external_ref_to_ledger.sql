-- supabase/migrations/20240101000003_add_external_ref_to_ledger.sql

-- Add an optional column to store external transaction references (e.g., Stripe Charge ID)
ALTER TABLE public.ledger_entries
ADD COLUMN external_reference TEXT NULL; 

COMMENT ON COLUMN public.ledger_entries.external_reference IS 'Optional reference ID from an external system (e.g., payment processor charge ID).'; 