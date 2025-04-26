-- supabase/migrations/20240101000001_create_post_ledger_transaction_rpc.sql

-- Function to post a transaction to the ledger, ensuring atomicity and checks.
CREATE OR REPLACE FUNCTION post_ledger_transaction(
    p_transaction_id UUID,
    p_debit_account_id UUID, 
    p_credit_account_id UUID,
    p_amount NUMERIC, -- Assumed to be positive
    p_currency VARCHAR(3),
    p_description TEXT,
    p_transaction_type VARCHAR(50),
    p_requesting_customer_id UUID -- The customer initiating the transaction
)
RETURNS UUID -- Returns the transaction_id on success
LANGUAGE plpgsql
SECURITY DEFINER -- Important: Runs with definer's permissions to insert into ledger
SET search_path = public -- Ensures we find the public tables
AS $$
DECLARE
    v_debit_account_currency VARCHAR(3);
    v_credit_account_currency VARCHAR(3);
    v_debit_account_customer_id UUID;
    v_current_balance NUMERIC;
BEGIN
    -- 1. Validate Amount
    IF p_amount <= 0 THEN
        RAISE EXCEPTION 'Amount must be positive';
    END IF;

    -- 2. Prevent self-transfer
    IF p_debit_account_id = p_credit_account_id THEN
        RAISE EXCEPTION 'Debit and credit accounts cannot be the same';
    END IF;

    -- 3. Get Account Details & Check Existence/Permissions
    SELECT currency, customer_id 
    INTO v_debit_account_currency, v_debit_account_customer_id
    FROM accounts
    WHERE id = p_debit_account_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Debit account not found: %', p_debit_account_id;
    END IF;

    SELECT currency 
    INTO v_credit_account_currency
    FROM accounts
    WHERE id = p_credit_account_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Credit account not found: %', p_credit_account_id;
    END IF;

    -- 4. Permission Check: Ensure requesting user owns the debit account
    IF v_debit_account_customer_id != p_requesting_customer_id THEN
         RAISE EXCEPTION 'Permission denied: Requesting user does not own debit account %', p_debit_account_id;
    END IF;

    -- 5. Currency Check
    IF v_debit_account_currency != p_currency OR v_credit_account_currency != p_currency THEN
        RAISE EXCEPTION 'Currency mismatch: Transaction currency (%) does not match account currencies (% / %)',
             p_currency, v_debit_account_currency, v_credit_account_currency;
    END IF;

    -- 6. Check Sufficient Funds (using calculate_balance for consistency)
    -- Lock the debit account row? For higher concurrency, calculating here might be better,
    -- but using the existing function ensures consistency.
    -- SELECT balance INTO v_current_balance FROM calculate_balance(p_debit_account_id);
    -- Let's calculate directly for atomicity within this transaction block
    SELECT COALESCE(SUM(amount), 0)
    INTO v_current_balance
    FROM ledger_entries
    WHERE account_id = p_debit_account_id;

    IF v_current_balance < p_amount THEN
        -- Use a custom SQLSTATE for specific error handling (e.g., P0001 for Insufficient Funds)
        RAISE EXCEPTION 'Insufficient funds in account % (Current Balance: %, Required: %)', p_debit_account_id, v_current_balance, p_amount
            USING ERRCODE = 'P0001'; 
    END IF;

    -- 7. Insert Ledger Entries (Debit first, then Credit)
    INSERT INTO ledger_entries (transaction_id, account_id, amount, currency, description, type)
    VALUES (p_transaction_id, p_debit_account_id, -p_amount, p_currency, p_description, p_transaction_type);

    INSERT INTO ledger_entries (transaction_id, account_id, amount, currency, description, type)
    VALUES (p_transaction_id, p_credit_account_id, p_amount, p_currency, p_description, p_transaction_type);

    -- 8. Return Transaction ID on success
    RETURN p_transaction_id;

END;
$$; 