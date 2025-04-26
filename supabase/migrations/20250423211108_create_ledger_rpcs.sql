-- Function to calculate the balance for a given account
CREATE OR REPLACE FUNCTION public.calculate_balance(p_account_id uuid)
RETURNS numeric(19, 4)
LANGUAGE sql
VOLATILE -- Changed from STABLE
AS $$
    SELECT 
        COALESCE(SUM(CASE WHEN entry_type = 'CREDIT' THEN amount ELSE 0 END), 0) - 
        COALESCE(SUM(CASE WHEN entry_type = 'DEBIT' THEN amount ELSE 0 END), 0)
    FROM public.ledger_entries
    WHERE account_id = p_account_id;
$$;

-- Function to post a double-entry transaction to the ledger
-- Ensures atomicity: both debit and credit entries succeed or fail together.
CREATE OR REPLACE FUNCTION public.post_ledger_transaction(
    p_transaction_id uuid,
    p_debit_account_id uuid,
    p_credit_account_id uuid,
    p_amount numeric(19, 4),
    p_currency character(3),
    p_description text DEFAULT NULL
)
RETURNS void -- Or potentially return the transaction_id or status
LANGUAGE plpgsql
-- SECURITY DEFINER -- Use with caution if RLS needs bypassing for inserts
AS $$
DECLARE
    v_current_balance numeric(19, 4);
BEGIN
    -- Explicitly lock the table to ensure consistent balance reading within the transaction
    LOCK TABLE public.ledger_entries IN SHARE ROW EXCLUSIVE MODE;

    -- Check if the debit account has sufficient funds
    -- Perform the check within the transaction to ensure atomicity and consistency.
    -- This relies on the current transaction isolation level.
    SELECT calculate_balance(p_debit_account_id) INTO v_current_balance;

    IF v_current_balance < p_amount THEN
       RAISE EXCEPTION 'Insufficient funds in account % (Current Balance: %, Required: %)', 
           p_debit_account_id, v_current_balance, p_amount
       USING ERRCODE = 'P0001'; -- Custom error code for insufficient funds
    END IF;

    -- Insert DEBIT entry
    INSERT INTO public.ledger_entries 
        (transaction_id, account_id, entry_type, amount, currency, description)
    VALUES 
        (p_transaction_id, p_debit_account_id, 'DEBIT', p_amount, p_currency, p_description);

    -- Insert CREDIT entry
    INSERT INTO public.ledger_entries 
        (transaction_id, account_id, entry_type, amount, currency, description)
    VALUES 
        (p_transaction_id, p_credit_account_id, 'CREDIT', p_amount, p_currency, p_description);

END;
$$;
