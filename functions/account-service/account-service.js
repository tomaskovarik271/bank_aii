const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto'); // For generating UUIDs (account numbers placeholder)
const { createJsonResponse } = require('../utils/responseUtils.js'); // <-- Import shared utility

// --- Environment Variable Configuration --- 
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const auth0Domain = process.env.AUTH0_DOMAIN;
const auth0Audience = process.env.AUTHBan_KEY;

// --- Initial Checks & Service Clients --- 
if (!supabaseUrl || !supabaseAnonKey || !auth0Domain || !auth0Audience) {
    console.error('FATAL: Missing required environment variables at startup.');
    // Consider throwing an error to prevent function startup
}

// --- Default Auth Token Verification Logic --- 
// This is the actual implementation
async function verifyTokenImplementation(authHeader) {
    // Require dependencies only when needed
    const jwt = require('jsonwebtoken');
    const { JwksClient } = require('jwks-rsa');

    // Setup JWKS client inside the function - ensures fresh instance if needed
const jwksRsaClient = new JwksClient({
    jwksUri: `https://${auth0Domain}/.well-known/jwks.json`,
        cache: true, // Consider test implications of cache
    rateLimit: true
});

function getSigningKey(header, callback) {
    jwksRsaClient.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error('Error getting signing key:', err);
            return callback(err);
        }
            const signingKey = key?.publicKey || key?.rsaPublicKey;
            if (!signingKey) {
                 console.error('Signing key not found for kid:', header.kid);
                 return callback(new Error('Signing key not found'));
            }
        callback(null, signingKey);
    });
}

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('verifyTokenImplementation: Missing or invalid auth header format.')
        throw { statusCode: 401, message: 'Missing or invalid Authorization header' };
    }
    const token = authHeader.substring(7);
    
    return new Promise((resolve, reject) => {
        jwt.verify(token, getSigningKey, { audience: auth0Audience, issuer: `https://${auth0Domain}/`, algorithms: ['RS256'] }, (err, decoded) => {
            if (err) {
                console.error('JWT verification error:', err.message);
                // Provide more specific error message if possible
                let statusCode = 401;
                let message = `Token verification failed: ${err.message}`;
                if (err.name === 'JsonWebTokenError') {
                    message = 'Forbidden: Invalid token';
                     statusCode = 403; // More appropriate status for invalid token
                } else if (err.name === 'TokenExpiredError') {
                    message = 'Forbidden: Token expired';
                    statusCode = 403;
            }
                 // Keep 401 for general verification issues like clock skew, audience/issuer mismatch?
                return reject({ statusCode, message });
            }
            if (!decoded || typeof decoded !== 'object') {
                 console.error('JWT decoded payload is invalid:', decoded);
                 return reject({ statusCode: 401, message: 'Invalid token payload' });
            }
            console.log('Token verified successfully by implementation.');
            resolve({ decoded: decoded, token: token }); 
        });
    });
}

// --- API Key Auth Logic (Placeholder - assumes direct RPC call) ---
async function getCustomerIdForApiKey(apiKey, _supabaseClient) {
     if (!apiKey) {
        throw { statusCode: 401, message: 'Missing API Key' }; // Or 403
    }
     console.log(`Verifying API Key: ${apiKey.substring(0, 5)}...`);
    const { data: customerId, error } = await _supabaseClient.rpc('get_customer_id_for_api_key', { p_api_key: apiKey });

    if (error) {
        console.error('Database error verifying API key:', error);
        throw { statusCode: 500, message: 'Database error verifying API key.' };
    }
    if (!customerId) {
        console.warn('Invalid API Key used.');
        throw { statusCode: 403, message: 'Forbidden: Invalid API Key' };
    }
    console.log(`API Key validated for customer ID: ${customerId}`);
    return customerId;
}

// --- Internal Handler with Dependency Injection --- 
async function handlerInternal(event, context, _getCustomerIdForApiKey = getCustomerIdForApiKey) {
     if (!supabaseUrl || !supabaseAnonKey) { // Removed auth0 checks as they are inside verifyTokenImpl
        console.error('HandlerInternal Error: Missing Supabase config.');
        return createJsonResponse(500, { message: 'Server configuration error' });
    }

    // --- Request Routing & Processing --- 
    const method = event.httpMethod;
    // Standardize path by removing potential prefix and forcing leading slash
    let standardizedPath = event.path.replace(/^\/?(?:\.netlify\/functions\/|api\/)?account-service/, '');
    if (!standardizedPath.startsWith('/')) {
        standardizedPath = '/' + standardizedPath;
    }
    standardizedPath = standardizedPath.replace(/\/$/, ''); // Remove trailing slash if exists (after prefix removal)
    if (standardizedPath === '') standardizedPath = '/'; // Handle root case

    let routeSegment = null;
    let accountIdFromPath = null;

    // Match structure first, validate UUID later. ID can be any char except '/'
    const accountTransactionsRegex = /^\/accounts\/([^/]+)\/transactions$/;
    const accountTransactionsMatch = standardizedPath.match(accountTransactionsRegex);

    // Match structure first, validate UUID later. ID can be any char except '/'
    const accountIdRegex = /^\/accounts\/([^/]+)$/;
    const accountIdMatch = standardizedPath.match(accountIdRegex);

    if (accountTransactionsMatch) {
        routeSegment = '/accounts/{accountId}/transactions';
        accountIdFromPath = accountTransactionsMatch[1];
        console.log(`Request received: ${method} ${event.path} (Route: ${routeSegment}, ID: ${accountIdFromPath})`);
    } else if (accountIdMatch) {
        routeSegment = '/accounts/{accountId}';
        accountIdFromPath = accountIdMatch[1];
        console.log(`Request received: ${method} ${event.path} (Route: ${routeSegment}, ID: ${accountIdFromPath})`);
    } else if (standardizedPath === '/accounts') {
        routeSegment = '/accounts';
        console.log(`Request received: ${method} ${event.path} (Route: ${routeSegment})`);
    } else {
        console.log(`Path ${event.path} (Standardized: ${standardizedPath}) does not match expected routes.`);
        // Route not matched, proceed to authentication then return 404 if auth passes
        // This allows auth errors (401/403) to be returned even for non-existent routes
    }

    // --- Authentication & Authorization --- 
    let auth0UserId = null;
    let customerId = null;
    let userSupabase = null; 
    let verifiedTokenPayload = null;
    let userJwt = null;
    const supabase = createClient(supabaseUrl, supabaseAnonKey); // Create base client

     try {
         const headers = event.headers || {};
         const authHeader = headers.authorization || headers.Authorization;
         const apiKey = headers['x-api-key'] || headers['X-Api-Key'];

         if (authHeader && authHeader.startsWith('Bearer ')) {
             // JWT Auth Path
             console.log('Attempting JWT authentication (using direct implementation call)...');
             const verificationResult = await verifyTokenImplementation(authHeader);
             verifiedTokenPayload = verificationResult.decoded;
             userJwt = verificationResult.token;
             auth0UserId = verifiedTokenPayload?.sub;
             if (!auth0UserId) throw { statusCode: 401, message: 'Invalid token: Missing subject claim.' };
             console.log(`JWT Token verified for sub: ${auth0UserId}`);
             userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
                 global: { headers: { Authorization: `Bearer ${userJwt}` } }
             });
             const { data: customerData, error: customerError } = await userSupabase
                 .from('customers').select('id').eq('auth0_user_id', auth0UserId).single();
             if (customerError || !customerData) throw { statusCode: 403, message: 'Forbidden: Customer profile required.' };
             customerId = customerData.id;
             console.log(`Customer ID found via JWT: ${customerId}`);

         } else if (apiKey) {
             // API Key Auth Path
             console.log('Attempting API Key authentication...');
             customerId = await _getCustomerIdForApiKey(apiKey, supabase);
             auth0UserId = null;
             console.log('Using anon Supabase client with fetched Customer ID for API Key flow.');
             userSupabase = supabase;
         } else {
             throw { statusCode: 401, message: 'Authentication required.' };
         }
         if (!customerId) throw { statusCode: 500, message: 'Internal server error: Failed to identify customer.' };

        // --- Route Handling --- 
        // Now check route segment *after* successful authentication
        if (routeSegment) {
            // Validate Account ID format *if* it was extracted
            if (accountIdFromPath) {
                 const fullAccountIdFormatRegex = /^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$/;
                 if (!fullAccountIdFormatRegex.test(accountIdFromPath)) {
                     console.warn(`Invalid Account ID format detected in path: ${accountIdFromPath}`);
                     return createJsonResponse(400, { message: 'Invalid Account ID format.' });
                 }
                 console.log(`Account ID format validated: ${accountIdFromPath}`);
            }
    
            // Use customerId and userSupabase client
            const accountId = accountIdFromPath; // Use consistent variable name
    
            // Check METHOD against the matched routeSegment
            // POST /accounts 
            if (method === 'POST' && routeSegment === '/accounts') {
                 console.log(`Handling POST /accounts for customer_id: ${customerId}`);
                 // Customer ID already fetched/verified via auth

                // Parse/Validate body 
                let requestBody = {};
                try {
                    requestBody = JSON.parse(event.body || '{}');
                } catch (parseError) {
                    return createJsonResponse(400, { message: 'Invalid JSON request body' });
                }

                // Validate request body
                const { account_type, currency, nickname } = requestBody;
                
                // Validate account_type FIRST
                if (!account_type || !['CHECKING', 'SAVINGS'].includes(account_type.toUpperCase())) {
                    // Update error message to reflect allowed types accurately
                    return createJsonResponse(400, { message: 'Missing or invalid required field: account_type (CHECKING or SAVINGS)' });
                }
                
                // Validate currency SECOND (BEFORE defaulting)
                if (!currency || typeof currency !== 'string' || currency.trim().length !== 3) {
                     return createJsonResponse(400, { message: 'Missing or invalid required field: currency (must be 3 characters)' });
                }
                const validCurrency = currency.trim().toUpperCase(); // Trim and uppercase AFTER validation

                // Generate account number (Placeholder)
                const accountNumber = crypto.randomUUID(); 

                // Prepare data for insertion
                const accountData = {
                    customer_id: customerId,
                    account_number: accountNumber,
                    account_type: account_type.toUpperCase(), // Already validated
                    currency: validCurrency, // Use validated & formatted currency
                    nickname: nickname || null, // Optional
                    // balance and is_active are set by DB default/trigger
                };

                // Insert using userSupabase
                const { data: newAccount, error: dbError } = await userSupabase
                    .from('accounts')
                    .insert(accountData)
                    .select()
                    .single();

                if (dbError) {
                    console.error('Supabase error creating account:', dbError);
                    if (dbError.code === '23505' && dbError.message.includes('accounts_account_number_key')) { 
                         return createJsonResponse(500, { message: 'Failed to generate unique account number. Please try again.' });
                    }
                    // Check for RLS violation error (might be generic permission error or specific code)
                    // For now, assume other errors are 500, but might indicate RLS failure on insert.
                    return createJsonResponse(500, { message: 'Database error creating account.' });
                }

                return createJsonResponse(201, newAccount);
            }
            // GET /accounts 
            else if (method === 'GET' && routeSegment === '/accounts') {
                 console.log(`Handling GET /accounts for customer_id: ${customerId}`);
                 // Customer ID already known from auth
                 // Remove query param validation for customerId

                 // RLS policy `select_own_accounts` needs to work with customer_id from API key flow
                 // or jwt sub for JWT flow.
                 const { data: accounts, error: dbError } = await userSupabase
                     .from('accounts')
                     .select('*')
                     .eq('customer_id', customerId); // Filter by the authenticated customer ID

                 if (dbError) {
                     console.error('Supabase error fetching accounts:', dbError);
                     return createJsonResponse(500, { message: 'Database error fetching accounts.' });
                 }

                 return createJsonResponse(200, accounts || []); 
            }
            // GET /accounts/{accountId}
            else if (method === 'GET' && routeSegment === '/accounts/{accountId}') {
                 console.log(`Handling GET /accounts/${accountId} for customer_id: ${customerId}`);
                 // 1. Check access via RPC
                 const { data: hasAccess, error: rpcError } = await userSupabase.rpc('check_account_access', { 
                     p_account_id: accountId, p_customer_id: customerId
                 });
                 
                 if (rpcError) {
                    console.error(`Database error checking account access for ${accountId}:`, rpcError);
                    throw { statusCode: 500, message: 'Database error checking account access.' };
                 }
                 if (!hasAccess) {
                     console.warn(`Access denied for customer ${customerId} to account ${accountId}`);
                      return createJsonResponse(404, { message: 'Account not found or access denied.' });
                 }
                 console.log(`Access verified for customer ${customerId} to account ${accountId}`);

                // 2. Fetch account details (we already know user has access)
                const { data: account, error: fetchError } = await userSupabase
                    .from('accounts')
                    .select('*') 
                    .eq('id', accountId)
                    .single();

                 if (fetchError || !account) { // Handle error or if account disappears
                      console.error(`Supabase error fetching account ${accountId} after access check:`, fetchError);
                       // If it disappears after access check, treat as not found
                      return createJsonResponse(404, { message: 'Account not found or access denied.' });
                 }

                 // 3. Calculate Balance by calling the RPC function
                 const { data: balanceValue, error: balanceRpcError } = await userSupabase.rpc('calculate_balance', { 
                     p_account_id: accountId 
                 });

                 if (balanceRpcError) {
                     console.error(`Error calling calculate_balance RPC for account ${accountId}:`, balanceRpcError);
                     // Decide if we should return 500 or the account data without balance
                     // For now, let's return 500 as balance is crucial
                     return createJsonResponse(500, { message: 'Error calculating account balance.' });
                }

                 // Add the calculated balance to the account object
                 // Ensure balanceValue is a number, default to 0 if null/undefined returned by RPC? Handle appropriately.
                 account.balance = (typeof balanceValue === 'number') ? balanceValue : 0; 

                 console.log(`Account ${accountId} fetched with balance: ${account.balance}`);
                 return createJsonResponse(200, account);
            }
            // POST /accounts/{accountId}/transactions 
            else if (method === 'POST' && routeSegment === '/accounts/{accountId}/transactions') {
                 console.log(`Handling POST /accounts/${accountId}/transactions for customer_id: ${customerId}`);
                 // 1. Check access via RPC
                 const { data: hasAccess, error: rpcError } = await userSupabase.rpc('check_account_access', { 
                     p_account_id: accountId, p_customer_id: customerId 
                 });
                 if (rpcError) {
                     console.error(`Database error checking POST transaction access for ${accountId}:`, rpcError);
                     return createJsonResponse(500, { message: 'Database error checking account access.' });
                }
                 if (!hasAccess) {
                     console.warn(`POST transaction access denied for customer ${customerId} to account ${accountId}`);
                     return createJsonResponse(404, { message: 'Account not found or access denied.' });
                }
                 console.log(`POST transaction access verified for customer ${customerId} to account ${accountId}`);
                 
                 // 2. Parse/Validate body - TODO WHEN IMPLEMENTING
                 // ...
                 
                 // --- Return 501 Not Implemented --- 
                 return createJsonResponse(501, { message: 'Transaction creation not implemented yet.' });

                /* // 3. Insert transaction (use authenticated customerId) - TODO WHEN IMPLEMENTING
                 const transactionData = { /* ..., account_id: accountId, customer_id: customerId * / };
                 const { data: newTransaction, error: insertError } = await userSupabase
                     .from('transactions')
                     .insert(transactionData)
                     .select()
                     .single();
                 if (insertError) { /* handle error * / }
                 
                 return createJsonResponse(201, newTransaction); // Return 201 Created
                */
            }
            // GET /accounts/{accountId}/transactions
            else if (method === 'GET' && routeSegment === '/accounts/{accountId}/transactions') {
                console.log(`Handling GET /accounts/${accountId}/transactions for customer_id: ${customerId}`);

                try {
                    // 1. Verify account access using the dedicated RPC
                    console.log(`Verifying access for customer ${customerId} to account ${accountId}...`);
                    const { error: accessError } = await userSupabase.rpc(
                        'check_account_access',
                        {
                            p_account_id: accountId,
                            p_requesting_customer_id: customerId
                        }
                    );

                    if (accessError) {
                        // Distinguish between permission errors and other DB errors
                        if (accessError.code === 'PGRST' && accessError.message.includes('Permission denied')) { // Check for specific permission error if possible
                            console.warn(`Access denied for customer ${customerId} to account ${accountId}:`, accessError.message);
                            return createJsonResponse(403, { message: 'Forbidden: You do not have access to this account.' });
                        } else {
                            console.error(`Database error during account access check for account ${accountId}:`, accessError);
                            return createJsonResponse(500, { message: 'Database error during access check.' });
                        }
                    }

                    // Supabase RPC might return { access_granted: true } or similar upon success, or just no error.
                    // Assuming no error means access is granted based on the RPC logic.
                    console.log(`Access verified for customer ${customerId} to account ${accountId}`);

                    // 2. Fetch transactions using the get_account_transactions RPC
                    console.log(`Fetching transactions for account ${accountId}...`);
                    const { data: transactions, error: txError } = await userSupabase.rpc(
                        'get_account_transactions',
                        {
                            p_account_id: accountId,
                            p_requesting_customer_id: customerId // Pass customerId again as required by the function
                        }
                    );

                    if (txError) {
                        // Handle potential errors from the transaction fetching RPC
                        // Could be account not found (if not caught by access check) or other issues
                        console.error(`Error fetching transactions for account ${accountId}:`, txError);
                         // Check if the error indicates the account wasn't found
                         if (txError.message.includes('Account not found') || txError.code === 'PGRST116') { // PGRST116 often means 'Row not found'
                            console.warn(`Account ${accountId} not found during transaction fetch.`);
                            return createJsonResponse(404, { message: `Account not found: ${accountId}` });
                        }
                        return createJsonResponse(500, { message: 'Error retrieving transactions.' });
                    }

                    console.log(`Successfully retrieved ${transactions?.length || 0} transactions for account ${accountId}.`);
                    return createJsonResponse(200, transactions || []); // Return empty array if null/undefined

                } catch (err) {
                    console.error(`Unexpected error processing GET /accounts/${accountId}/transactions:`, err);
                    return createJsonResponse(500, { message: 'An unexpected error occurred.' });
                }
            }
            // PATCH /accounts/{accountId} - Update account nickname
            else if (method === 'PATCH' && routeSegment === '/accounts/{accountId}') {
                 console.log(`DEBUG_PATCH: Entering PATCH handler for account ${accountId}, customer ${customerId}`);
                 // 1. Parse Body (Only nickname is updatable for now)
                 let requestBody = {};
                 try {
                     requestBody = JSON.parse(event.body || '{}');
                 } catch (parseError) {
                     return createJsonResponse(400, { message: 'Invalid JSON request body' });
                 }

                 const { nickname } = requestBody;
                 if (nickname === undefined || typeof nickname !== 'string') {
                     return createJsonResponse(400, { message: 'Missing or invalid field: nickname (must be a string).' });
                 }

                 // 2. Check access via RPC (same as GET)
                 const { data: hasAccess, error: rpcError } = await userSupabase.rpc('check_account_access', { 
                      p_account_id: accountId, 
                      p_customer_id: customerId
                 });
                 if (rpcError) {
                      console.error(`Database error checking PATCH account access for ${accountId}:`, rpcError);
                      return createJsonResponse(500, { message: 'Database error checking account access.' });
                 }
                 if (!hasAccess) {
                      console.warn(`PATCH access denied for customer ${customerId} to account ${accountId}`);
                      return createJsonResponse(404, { message: 'Account not found or access denied.' });
                 }
                 console.log(`PATCH access verified for customer ${customerId} to account ${accountId}`);

                 // 3. Perform Update (Rely on RLS `update_own_accounts` as well)
                  const { data: updatedAccount, error: updateError } = await userSupabase
                     .from('accounts')
                     .update({ nickname: nickname })
                     .eq('id', accountId)
                     // Optionally add .eq('customer_id', customerId) for belt-and-suspenders, 
                     // though check_account_access + RLS should cover it.
                     .select()
                     .single();

                 if (updateError) {
                      console.error(`Supabase error updating account ${accountId}:`, updateError);
                      // Check if RLS caused the update to fail (might be PGRST116 if no rows updated)
                      if (updateError.code === 'PGRST116') {
                          return createJsonResponse(404, { message: 'Account not found for update.' });
                      }
                      return createJsonResponse(500, { message: 'Database error updating account.' });
                 }
                 
                 // Handle case where update succeeded but returned no data (shouldn't happen with .single() error check)
                 if (!updatedAccount) {
                      return createJsonResponse(404, { message: 'Account not found for update.' });
                 }
                 
                  // Note: We don't return balance here as it requires another RPC call.
                  // Client should re-fetch if they need the latest balance.
                 return createJsonResponse(200, updatedAccount);
            }
            // DELETE /accounts/{accountId} - Delete account
            else if (method === 'DELETE' && routeSegment === '/accounts/{accountId}') {
                console.log(`Handling DELETE /accounts/${accountId} for customer_id: ${customerId}`);
                // 1. Check access via RPC
                const { data: hasAccess, error: rpcError } = await userSupabase.rpc('check_account_access', { 
                     p_account_id: accountId, 
                     p_customer_id: customerId
                });
                 if (rpcError) {
                     console.error(`Database error checking DELETE account access for ${accountId}:`, rpcError);
                     return createJsonResponse(500, { message: 'Database error checking account access.' });
                }
                if (!hasAccess) {
                     console.warn(`DELETE access denied for customer ${customerId} to account ${accountId}`);
                     return createJsonResponse(404, { message: 'Account not found or access denied.' });
            }
                console.log(`DELETE access verified for customer ${customerId} to account ${accountId}`);
                
                // TODO: Consider adding a check here: Should deletion be allowed if balance != 0?
                // const { data: balanceValue, error: balanceRpcError } = await userSupabase.rpc(...) etc.

                // 2. Perform Delete (Rely on RLS `delete_own_accounts` - needs creation)
                const { error: deleteError, count } = await userSupabase
                    .from('accounts')
                    .delete()
                    .eq('id', accountId);
                    // Optionally add .eq('customer_id', customerId)
                    
                if (deleteError) {
                     console.error(`Supabase error deleting account ${accountId}:`, deleteError);
                     // Handle potential FK constraint errors if transactions exist?
                     return createJsonResponse(500, { message: 'Database error deleting account.' });
                }

                if (count === 0) {
                     // This implies the account didn't exist or RLS prevented the delete
                     return createJsonResponse(404, { message: 'Account not found for deletion.' });
                }
                
                console.log(`Successfully deleted account ${accountId} for customer ${customerId}`);
                return { statusCode: 204 }; // 204 No Content
            }
            // Fallback: Valid Route, Invalid Method
            else {
                 console.log(`Method ${method} not allowed for route ${routeSegment}`);
                 return createJsonResponse(405, { message: 'Method Not Allowed' });
            }
        }
        // CASE 2: No Valid Route Segment Matched initially
        else {
            console.log(`Path ${event.path} (Standardized: ${standardizedPath}) does not match expected routes.`);
            return createJsonResponse(404, { message: 'Function route not found' });
        }

    } catch (error) {
        // --- Centralized Error Handling --- 
        console.error('Function Error:', error);
        // Ensure statusCode and message are present
        const statusCode = error.statusCode || 500;
        // Use a generic message for 500, specific for others, unless original is missing
        let responseMessage = error.message || (statusCode === 500 ? 'Internal Server Error' : 'An error occurred');
        if (statusCode === 500 && error.message) {
            // If it's a 500 AND we have an original message, use a generic top-level message
            responseMessage = 'Internal Server Error'; 
        }
        
        // Prepare response body
        const responseBody = { message: responseMessage };
        // Include original error details for 500 errors if the error object might contain useful info
        if (statusCode === 500 && error?.message) {
             // Add the original error message under the 'error' key
             responseBody.error = error.message;
        }
        
        return createJsonResponse(statusCode, responseBody);
    }
}

// --- Netlify Handler Export --- 
// This remains the entry point for Netlify
exports.handler = async (event, context) => {
    // Calls the internal handler, using default implementations for auth functions
    return handlerInternal(event, context); 
}; 

// --- Exports for Testing --- 
module.exports = {
    handler: exports.handler,
    handlerInternal, 
    verifyTokenImplementation, // Export original implementation if needed for specific tests
    getCustomerIdForApiKey // Export API key function for potential mocking
}; 