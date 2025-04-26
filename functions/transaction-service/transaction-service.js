const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');
const crypto = require('crypto'); // For generating transaction ID
const { createJsonResponse } = require('../utils/responseUtils.js'); // <-- Import shared utility

// --- Environment Variable Configuration --- 
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const auth0Domain = process.env.AUTH0_DOMAIN;
const auth0Audience = process.env.AUTH0_AUDIENCE;

// --- Initial Checks & Service Clients --- 
// Basic check for required env vars (can be done outside handler for efficiency)
if (!supabaseUrl || !supabaseAnonKey || !auth0Domain || !auth0Audience) {
    console.error('FATAL: Missing required environment variables at startup.');
    // Optionally throw an error to prevent the function from being served if critical config is missing
    // throw new Error("Missing required environment variables"); 
}

// Initialize JWKS client to fetch Auth0 public keys for token verification
const jwksRsaClient = new JwksClient({
    jwksUri: `https://${auth0Domain}/.well-known/jwks.json`,
    cache: true, // Cache signing keys for performance
    rateLimit: true // Prevent abuse
});

// --- Auth Token Verification Logic --- 

/**
 * Fetches the appropriate RSA public key from the Auth0 JWKS endpoint based on the JWT header's key ID (kid).
 * @param {object} header The decoded header of the JWT.
 * @param {string} header.kid The key ID from the JWT header.
 * @param {function} callback Callback function `(err, key)` called by `jwt.verify`.
 */
function getSigningKey(header, callback) {
    jwksRsaClient.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error('Error getting signing key:', err);
            return callback(err);
        }
        const signingKey = key.publicKey || key.rsaPublicKey;
        if (!signingKey) {
            console.error('Signing key not found for kid:', header.kid);
            return callback(new Error('Signing key not found'));
        }
        callback(null, signingKey);
    });
}

/**
 * Verifies the signature, audience, issuer, and expiration of an Auth0 JWT passed in the Authorization header.
 *
 * @param {string | undefined} authHeader The content of the Authorization header (e.g., "Bearer ey...").
 * @returns {Promise<{decoded: object, token: string}>} A promise that resolves with the decoded JWT payload and the original token string if verification is successful.
 * @throws {{statusCode: number, message: string}} Throws an error object with statusCode 401 if the header is missing, malformed, or the token is invalid.
 */
async function verifyToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Standard practice to return 401 for missing/malformed auth
        throw { statusCode: 401, message: 'Missing or invalid Authorization header. Expected: Bearer <token>' };
    }
    // Extract token part after "Bearer "
    const token = authHeader.substring(7);

    return new Promise((resolve, reject) => {
        jwt.verify(token, getSigningKey, {
            audience: auth0Audience, // Verify token is intended for our API
            issuer: `https://${auth0Domain}/`, // Verify token was issued by our Auth0 domain
            algorithms: ['RS256'] // Ensure the expected algorithm is used
        }, (err, decoded) => {
            if (err) {
                console.error('JWT verification error:', err);
                // Map JWT errors (like expiration, invalid signature) to 401
                return reject({ statusCode: 401, message: `Token verification failed: ${err.message}` });
            }
            if (!decoded || typeof decoded !== 'object') {
                console.error('JWT decoded payload is invalid:', decoded);
                return reject({ statusCode: 401, message: 'Invalid token payload' });
            }
            console.log(`Token verified for sub: ${decoded.sub}, grant_type: ${decoded.gty}`);
            // Token is valid, resolve with the decoded payload AND the original token
            resolve({ decoded: decoded, token: token }); // Contains claims like sub, scope, etc.
        });
    });
}

// --- API Key Auth Logic (Placeholder - assumes direct RPC call) --
async function getCustomerIdForApiKeyImplementation(apiKey, _supabaseClient) {
    if (!apiKey) {
        throw { statusCode: 401, message: 'Missing API Key' }; // Or 403
    }
    console.log(`Verifying API Key: ${apiKey.substring(0, 5)}...`);
    // Assume anon client passed in is sufficient
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
async function handlerInternal(event, context, _verifyToken = verifyToken, _getCustomerIdForApiKey = getCustomerIdForApiKeyImplementation) {
    // Re-check critical env vars within the handler context as a safeguard
    if (!supabaseUrl || !supabaseAnonKey || !auth0Domain || !auth0Audience) {
        console.error('Handler Error: Missing required environment variables.');
        return createJsonResponse(500, { message: 'Server configuration error' });
    }

    // --- Request Routing & Processing --- 
    let routeSegment = null; // Define route segment variable
    const method = event.httpMethod;
    // Standardize path
    let standardizedPath = event.path.replace(/^\/?(?:\.netlify\/functions\/|api\/)?transaction-service/, '');
    if (!standardizedPath.startsWith('/')) {
        standardizedPath = '/' + standardizedPath;
    }
    standardizedPath = standardizedPath.replace(/\/?$/, ''); // Remove trailing slash more robustly
    if (standardizedPath === '') standardizedPath = '/'; // Handle root case

    console.log(`Request received: ${method} ${event.path} (SubPath: ${standardizedPath})`);

    // Basic Route Matching
    if (standardizedPath === '/status') {
        routeSegment = '/status';
    } else if (standardizedPath === '/internal-transfer') {
        routeSegment = '/internal-transfer';
    } else if (standardizedPath === '/transactions/external') {
        routeSegment = '/transactions/external';
    } // Add more routes here

    // --- Authentication & Client Setup --- 
    let auth0UserId = null;
    let customerId = null; // Used only for API Key flow in this service
    let supabase = null; // Will hold either user-scoped or anon client
    let isApiKeyAuth = false; // Flag to track auth type

    try {
        // Normalize headers to lowercase for consistent access
        const rawHeaders = event.headers || {};
        const headers = Object.keys(rawHeaders).reduce((acc, key) => {
            acc[key.toLowerCase()] = rawHeaders[key];
            return acc;
        }, {});

        // --- Critical Lines --- Using normalized headers
        const authHeader = headers['authorization']; // Access lowercase key
        const apiKey = headers['x-api-key'];     // Access lowercase key
        const baseSupabaseClient = createClient(supabaseUrl, supabaseAnonKey); // Base anon client

        // <<< REMOVE TEMPORARY DEBUG LOG (or keep it commented out) >>>
        // console.log(`DEBUG: Headers = ${JSON.stringify(headers)}, authHeader = ${authHeader}, apiKey = ${apiKey}`);

        if (authHeader && authHeader.startsWith('Bearer ')) {
            console.log('Attempting JWT authentication...');
            const verifiedToken = await _verifyToken(authHeader); // Use injected verify function
            auth0UserId = verifiedToken.decoded.sub;
            supabase = createClient(supabaseUrl, supabaseAnonKey, {
                global: { headers: { Authorization: `Bearer ${verifiedToken.token}` } }
            });
            console.log('JWT authentication successful.');

        } else if (apiKey) {
            console.log('Attempting API Key authentication...');
            // customerId = await _getCustomerIdForApiKey(apiKey, baseSupabaseClient); // Use injected get function -- UNUSED
            await _getCustomerIdForApiKey(apiKey, baseSupabaseClient); // Still call it, but don't store the result
            supabase = baseSupabaseClient; // Use base anon client for API key requests
            isApiKeyAuth = true;
            console.log('API Key authentication successful.');
        } else {
            throw { statusCode: 401, message: 'Authentication required.' };
        }

        // --- Route Handling (Post-Auth) ---
        if (routeSegment === '/status' && method === 'GET') {
            // Basic health check requires auth but doesn't do much else
            return createJsonResponse(200, { status: 'OK' }); // Simpler response

        } else if (routeSegment === '/internal-transfer' && method === 'POST') {
            // Ensure JWT auth was used for this route
            if (isApiKeyAuth) {
                return createJsonResponse(403, { message: 'Forbidden: JWT required for internal transfers.' });
            }
            // Ensure auth0UserId is available (should be if !isApiKeyAuth)
            if (!auth0UserId) {
                throw { statusCode: 500, message: 'Internal Server Error: User ID missing after JWT auth.' };
            }
            
            console.log('>>> [transaction-service] Handling POST /internal-transfer Start.');
             
            // 1. Parse and Validate Request Body
            let requestBody = {};
            try {
                requestBody = JSON.parse(event.body || '{}');
            } catch (parseError) {
                console.error('>>> [transaction-service] Invalid JSON body.', parseError);
                return createJsonResponse(400, { message: 'Invalid JSON request body' });
            }
 
            const { fromAccountId, toAccountId, amount, currency, description } = requestBody;
            // Log transfer details
            console.log(`>>> [transaction-service] Transfer details: From=${fromAccountId}, To=${toAccountId}, Amount=${amount}, Currency=${currency}`);
 
            const errors = [];
            if (!fromAccountId || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(fromAccountId)) {
                errors.push('Missing or invalid fromAccountId (must be UUID).');
            }
            if (!toAccountId || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(toAccountId)) {
                errors.push('Missing or invalid toAccountId (must be UUID).');
            }
            if (fromAccountId === toAccountId) {
                 errors.push('fromAccountId and toAccountId cannot be the same.');
            }
            if (typeof amount !== 'number' || amount <= 0) {
                errors.push('Missing or invalid amount (must be positive number).');
            }
            if (!currency || typeof currency !== 'string' || currency.length !== 3) {
                errors.push('Missing or invalid currency (must be 3-letter code).');
            }
            if (errors.length > 0) {
                console.warn('>>> [transaction-service] Validation failed:', errors);
                return createJsonResponse(400, { message: 'Invalid request', errors });
            }
 
            // Verify ownership/existence of the source account via RLS using user-scoped client
            console.log(`>>> [transaction-service] Verifying source account ownership for ${fromAccountId}...`);
            const { data: checkData, error: checkOwnerError } = await supabase // Use the authenticated client (userSupabase == supabase here)
                .from('accounts') // Check the actual accounts table now
                .select('id, customer_id') // Select customer_id for explicit check
                .eq('id', fromAccountId)
                .single(); 
 
            if (checkOwnerError) {
                console.error(`>>> [transaction-service] RLS/Existence check failed for source account ${fromAccountId}:`, checkOwnerError);
                 // If RLS prevents select or account doesn't exist, PGRST116 might occur
                 if (checkOwnerError.code === 'PGRST116') { 
                      return createJsonResponse(404, { message: `Source account not found: ${fromAccountId}` });
                 }
                 // Other DB errors during check
                 return createJsonResponse(500, { message: `Database error verifying source account: ${fromAccountId}` });
            }
            // Explicitly check if the fetched customer_id matches the authenticated user's ID (now stored in auth0UserId)
            if (!checkData || checkData.customer_id !== auth0UserId) {
                 console.warn(`>>> [transaction-service] Permission denied. Auth user ${auth0UserId} does not match owner ${checkData?.customer_id} for account ${fromAccountId}`);
                 return createJsonResponse(403, { message: `Permission denied for source account: ${fromAccountId}` });
            }
            console.log(`>>> [transaction-service] Source account ownership verified for ${fromAccountId}.`);
 
            // 4. Generate Transaction ID
            const transactionId = crypto.randomUUID();
            console.log(`>>> [transaction-service] Generated Transaction ID: ${transactionId}`);
 
            // 5. Call the RPC function using the *user-scoped* client
            console.log(`>>> [transaction-service] Calling RPC post_ledger_transaction for TxID ${transactionId}...`);
            const { error: rpcError } = await supabase.rpc('post_ledger_transaction', {
                 p_transaction_id: transactionId,
                 p_debit_account_id: fromAccountId,
                 p_credit_account_id: toAccountId,
                 p_amount: amount, 
                 p_currency: currency.toUpperCase(), // Ensure consistent case
                 p_description: description || `Transfer from ${fromAccountId} to ${toAccountId}`, // Default description
                 p_transaction_type: 'TRANSFER', // Hardcode type for this endpoint
                 p_requesting_customer_id: auth0UserId // Pass the authenticated user ID
             });
 
            // Log RPC result
            if (rpcError) {
                // Check for specific, user-facing errors first
                if (rpcError.code === 'P0001') { // Custom code for insufficient funds
                    console.log(`>>> [transaction-service] Insufficient funds error detected for TxID ${transactionId}. Returning 422.`);
                    return createJsonResponse(422, { 
                        message: rpcError.message || 'Insufficient funds', // Use message from DB if available
                        transactionId: transactionId, 
                        code: 'INSUFFICIENT_FUNDS'
                    });
                }
                 // Handle other potential specific RPC errors (e.g., account not found, currency mismatch if raised by RPC)
                 if (rpcError.message.includes('account not found') || rpcError.message.includes('Currency mismatch') || rpcError.message.includes('Debit and credit accounts cannot be the same')) {
                      console.warn(`>>> [transaction-service] RPC validation error for TxID ${transactionId}: ${rpcError.message}`);
                      return createJsonResponse(400, { // Bad request because input was invalid
                           message: rpcError.message, 
                           transactionId: transactionId, 
                           code: 'INVALID_TRANSFER_DETAILS'
                     });
                 }
                 if (rpcError.message.includes('Permission denied')) {
                      console.warn(`>>> [transaction-service] RPC permission error for TxID ${transactionId}: ${rpcError.message}`);
                       return createJsonResponse(403, { // Forbidden 
                           message: 'Permission denied for source account.', 
                           transactionId: transactionId, 
                           code: 'PERMISSION_DENIED'
                      });
                 }
                // Handle generic/unexpected database errors from RPC
                console.error(`>>> [transaction-service] Unhandled RPC error for TxID ${transactionId}. Returning 500.`);
                return createJsonResponse(500, { 
                    message: 'Failed to process transfer due to a database error.', 
                    transactionId: transactionId, 
                    code: 'TRANSFER_FAILED' // Generic failure code
                });
            }
 
            // --- Success --- 
            console.log(`>>> [transaction-service] Transfer successful for TxID ${transactionId}. Returning 200.`);
            return createJsonResponse(200, { 
                message: 'Transfer successful', 
                transactionId: transactionId 
            });

        } else if (routeSegment === '/transactions/external' && method === 'POST') {
            // Ensure API Key auth was used for this route
            if (!isApiKeyAuth) {
                console.warn('Attempted POST /transactions/external without API key auth.');
                return createJsonResponse(403, { message: 'Forbidden: API Key required for this operation.' });
            }
            console.log('API Key authentication verified for /transactions/external.');

            // 2. Parse and Validate Body
             let requestBody = {};
             try {
                 requestBody = JSON.parse(event.body || '{}');
             } catch (parseError) {
                 return createJsonResponse(400, { message: 'Invalid JSON request body' });
             }
 
             const { accountId, amount, currency, description, externalReference } = requestBody;
 
             // Simplified Validation: Check only for presence/basic type of required fields
              if (!accountId || typeof accountId !== 'string') { // Basic presence and type check only
                  return createJsonResponse(400, { message: 'Missing or invalid required field: accountId (must be a string)' });
              }
              if (amount === undefined || typeof amount !== 'number') { // Basic type check only
                  return createJsonResponse(400, { message: 'Missing or invalid required field type: amount (must be a number)' });
              }
              if (!currency || typeof currency !== 'string') { // Basic type check only
                  return createJsonResponse(400, { message: 'Missing or invalid required field type: currency (must be a string)' });
              }
               if (!description || typeof description !== 'string') { // Basic type check only
                   return createJsonResponse(400, { message: 'Missing or invalid required field: description' });
               }
                if (externalReference !== undefined && typeof externalReference !== 'string') {
                     return createJsonResponse(400, { message: 'Invalid field type: externalReference (must be a string if provided)' });
                }

            // 3. Call the RPC function (using the base/anon client `supabase`)
             console.log(`Calling RPC post_external_deposit for account ${accountId}`);
             const { data: rpcData, error: rpcError } = await supabase.rpc('post_external_deposit', {
                 p_account_id: accountId,
                 p_amount: amount,
                 p_currency: currency.toUpperCase(), // Ensure consistent case
                 p_description: description.trim(),
                 p_external_reference: externalReference || null
             });

            // 4. Handle RPC Errors (copied from previous version)
             if (rpcError) {
                 console.error(`Supabase RPC error posting external deposit for account ${accountId}:`, rpcError);
                 // Rely on RPC error messages for specific feedback
                 if (rpcError.message.includes('Account not found')) {
                      return createJsonResponse(404, { message: `Validation Error: Account not found: ${accountId}` });
                  } else if (rpcError.message.includes('Account is inactive')) {
                      return createJsonResponse(400, { message: `Validation Error: Account is inactive: ${accountId}` });
                  } else if (rpcError.message.includes('Currency mismatch')) {
                      return createJsonResponse(400, { message: `Validation Error: ${rpcError.message}` });
                  }
                  // Default fallback for other/generic RPC errors
                  return createJsonResponse(500, { message: 'Database error processing deposit.' });
              }

            // 5. Return Success
             console.log(`External deposit successful for account ${accountId}, Ledger Entry ID: ${rpcData?.id}`);
             return createJsonResponse(201, rpcData);

        } else {
            // Route not found or method not allowed for matched route segment
            console.log(`Route ${routeSegment} with method ${method} not handled.`);
            return createJsonResponse(404, { message: 'Transaction Service route not found' });
        }

    } catch (error) {
        // --- Centralized Error Handling --- 
        console.error('Function Error:', error);
        const statusCode = error.statusCode || 500;
        const responseMessage = error.message || 'Internal Server Error';
        return createJsonResponse(statusCode, { message: responseMessage });
    }
}

// --- Netlify Handler Export --- 
exports.handler = async (event, context) => {
    // Pass the actual external function implementations
    return handlerInternal(event, context, verifyToken, getCustomerIdForApiKeyImplementation);
}; 

// --- Exports for Testing --- 
module.exports = {
    handler: exports.handler,
    handlerInternal, 
    verifyToken, 
    getCustomerIdForApiKeyImplementation 
}; 