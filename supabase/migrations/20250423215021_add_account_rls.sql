-- Enable RLS policies for the accounts table
-- Assumes RLS is already enabled on the table (done in init_schema migration)

-- Helper function to get the customer_id associated with the current auth user
-- Returns NULL if no matching customer found.
CREATE OR REPLACE FUNCTION public.get_my_customer_id()
RETURNS uuid
LANGUAGE sql
STABLE -- Doesn't modify the database, results depend only on inputs (implicit auth.uid())
SECURITY DEFINER -- Allows the function to query customers table even if user has no direct select rights
AS $$
  SELECT id FROM public.customers WHERE auth0_user_id = (auth.uid())::text;
$$;

-- Grant execute permission on the helper function to authenticated users
GRANT EXECUTE ON FUNCTION public.get_my_customer_id() TO authenticated;

-- Policy: Allow users to select their own accounts
CREATE POLICY select_own_accounts
ON public.accounts
FOR SELECT
USING (customer_id = public.get_my_customer_id());

-- Policy: Allow users to insert accounts linked to their own customer record
CREATE POLICY insert_own_accounts
ON public.accounts
FOR INSERT
WITH CHECK (customer_id = public.get_my_customer_id());

-- Policy: Allow users to update their own accounts (e.g., nickname, status)
CREATE POLICY update_own_accounts
ON public.accounts
FOR UPDATE
USING (customer_id = public.get_my_customer_id())
WITH CHECK (customer_id = public.get_my_customer_id());

-- Note: DELETE policy is omitted for now.
