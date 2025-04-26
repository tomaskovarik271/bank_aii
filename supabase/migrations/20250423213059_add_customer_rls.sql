-- Enable RLS policies for the customers table
-- Assumes RLS is already enabled on the table (done in init_schema migration)

-- Policy: Allow users to select their own customer record
CREATE POLICY select_own_customer 
ON public.customers
FOR SELECT
USING (auth0_user_id = (auth.uid())::text); -- Cast auth.uid() to text for comparison

-- Policy: Allow users to update their own customer record
CREATE POLICY update_own_customer 
ON public.customers
FOR UPDATE
USING (auth0_user_id = (auth.uid())::text) -- Cast auth.uid() to text
WITH CHECK (auth0_user_id = (auth.uid())::text); -- Cast auth.uid() to text

-- Note: INSERT is currently handled by the Netlify function using the service_role key,
-- which bypasses RLS. If direct INSERTs by users were needed, an INSERT policy would be required.
-- Note: DELETE policy is omitted for now. Consider adding one based on requirements.
