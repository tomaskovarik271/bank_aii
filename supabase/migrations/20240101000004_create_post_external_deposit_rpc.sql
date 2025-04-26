-- supabase/migrations/20240101000004_create_post_external_deposit_rpc.sql

-- Function to post a single credit ledger entry for an external deposit.
-- This doesn't require customer ID for permission check, assuming authorization
-- is handled at the service layer (e.g., via API key validation).
CREATE OR REPLACE FUNCTION post_external_deposit(
    p_account_id UUID,
    p_amount NUMERIC(19, 4), -- Same precision as ledger_entries.amount
    p_currency TEXT,
    p_description TEXT,
    p_external_reference TEXT DEFAULT NULL -- Optional external reference
)
RETURNS ledger_entries -- Return the created ledger entry
LANGUAGE plpgsql
SECURITY DEFINER -- Run with definer's permissions to check accounts
SET search_path = public
AS $$
DECLARE
    v_account_currency TEXT;
    v_account_exists BOOLEAN;
    v_new_ledger_entry ledger_entries;
    v_transaction_id UUID := gen_random_uuid(); -- Generate a unique ID for this deposit
BEGIN
    -- 1. Validate Amount
    IF p_amount <= 0 THEN
        RAISE EXCEPTION 'Deposit amount must be positive.';
    END IF;

    -- 2. Validate Account and Currency
    SELECT currency, is_active INTO v_account_currency, v_account_exists
    FROM accounts
    WHERE id = p_account_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found: %', p_account_id;
    END IF;

    IF NOT v_account_exists THEN
        RAISE EXCEPTION 'Account is inactive: %', p_account_id;
    END IF;

    IF upper(v_account_currency) != upper(p_currency) THEN
        RAISE EXCEPTION 'Currency mismatch: Account currency is %, deposit currency is %', v_account_currency, p_currency;
    END IF;

    -- 3. Insert Credit Ledger Entry
    INSERT INTO ledger_entries (
        account_id,
        transaction_id, -- Link this deposit to a unique transaction
        amount,         -- Positive amount for credit
        currency,
        type,
        description,
        external_reference
    )
    VALUES (
        p_account_id,
        v_transaction_id,
        p_amount,       -- Store as positive
        upper(p_currency),
        'DEPOSIT',      -- Use a specific type for external deposits
        p_description,
        p_external_reference
    )
    RETURNING * INTO v_new_ledger_entry;

    RETURN v_new_ledger_entry;
END;
$$; 