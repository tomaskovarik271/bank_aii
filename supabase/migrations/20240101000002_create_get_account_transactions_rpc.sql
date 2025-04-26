-- supabase/migrations/20240101000002_create_get_account_transactions_rpc.sql

-- Function to retrieve ledger entries for a specific account, checking permissions.
CREATE OR REPLACE FUNCTION get_account_transactions(
    p_account_id UUID,
    p_requesting_customer_id UUID
)
-- Returns a set of ledger_entries records
RETURNS SETOF ledger_entries 
LANGUAGE plpgsql
SECURITY DEFINER -- Run with definer's permissions to check accounts table
SET search_path = public
AS $$
DECLARE
    v_account_customer_id UUID;
BEGIN
    -- 1. Check Permission: Verify the requesting user owns the account
    SELECT customer_id 
    INTO v_account_customer_id
    FROM accounts
    WHERE id = p_account_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found: %', p_account_id;
    END IF;

    IF v_account_customer_id != p_requesting_customer_id THEN
         RAISE EXCEPTION 'Permission denied: Requesting user does not own account %', p_account_id;
    END IF;

    -- 2. Return Ledger Entries for the account
    -- Order by timestamp descending to show most recent first
    RETURN QUERY 
    SELECT *
    FROM ledger_entries
    WHERE account_id = p_account_id
    ORDER BY created_at DESC;

END;
$$; 