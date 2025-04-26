// functions/customer-service/customer-service.js
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');
const { createJsonResponse } = require('../utils/responseUtils.js'); // <-- Import shared utility

// --- Environment Variable Configuration --- 
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const auth0Domain = process.env.AUTH0_DOMAIN;
const auth0Audience = process.env.AUTH0_AUDIENCE;

// --- Initial Checks & Service Clients --- 
// Basic check for required env vars (can be done outside handler for efficiency)
if (!supabaseUrl || !supabaseAnonKey || !auth0Domain || !auth0Audience) {
    console.error('FATAL: Missing required environment variables at startup (SUPABASE_URL, SUPABASE_ANON_KEY, AUTH0_DOMAIN, AUTH0_AUDIENCE).');
    // Optionally throw an error to prevent the function from being served if critical config is missing
    // throw new Error("Missing required environment variables"); 
}

// Initialize JWKS client to fetch Auth0 public keys for token verification
const jwksRsaClient = new JwksClient({
    jwksUri: `https://${auth0Domain}/.well-known/jwks.json`,
    cache: false, // <-- MODIFIED: Disable cache for debugging
    rateLimit: true // Prevent abuse
});

// --- Auth Token Verification Logic (Copied from transaction-service) --- 

/**
 * Fetches the appropriate RSA public key from the Auth0 JWKS endpoint based on the JWT header's key ID (kid).
 * This key is used by `jwt.verify` to validate the token signature.
 * Uses the jwks-rsa client with caching and rate limiting.
 *
 * @param {object} header The decoded header of the JWT.
 * @param {string} header.kid The key ID from the JWT header.
 * @param {function} callback Callback function `(err, key)` called by `jwt.verify`.
 */
function getSigningKey(header, callback) {
    jwksRsaClient.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error('Error getting signing key from JWKS:', err); // Log full error
            return callback(err);
        }
        console.log('Successfully fetched signing key:', JSON.stringify(key, null, 2)); 
        const signingKey = key.publicKey || key.rsaPublicKey;
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
        throw { statusCode: 401, message: 'Missing or invalid Authorization header. Expected: Bearer <token>' };
    }
    const token = authHeader.substring(7);

    return new Promise((resolve, reject) => {
        jwt.verify(token, getSigningKey, {
            audience: auth0Audience,
            issuer: `https://${auth0Domain}/`,
            algorithms: ['RS256']
        }, (err, decoded) => {
            if (err) {
                console.error('JWT verification error:', err); // Log the full error object
                return reject({ statusCode: 401, message: `Token verification failed: ${err.message}` });
            }
            // Token is valid, resolve with the decoded payload AND the original token
            resolve({ decoded: decoded, token: token }); // Contains claims like sub, scope, etc.
        });
    });
}

// --- Main Netlify Function Handler --- 

/**
 * Internal logic handler for Customer Service.
 * Moved here for testability.
 */
async function handlerInternal(event, context) { // <-- NEW Internal Function
    // Re-check critical env vars within the handler context as a safeguard
    if (!supabaseUrl || !supabaseAnonKey || !auth0Domain || !auth0Audience) {
        console.error('Handler Error: Missing required environment variables.');
        return createJsonResponse(500, { message: 'Server configuration error' });
    }

    // --- Request Routing & Processing --- 
    const subPath = event.path.replace(/^\/?(\.netlify\/functions\/|api\/)?customer-service/, '') || '/'; 
    const method = event.httpMethod;
    console.log(`Request received: ${method} ${event.path} (SubPath: ${subPath})`);

    try {
        // --- Authentication --- 
        // Check both standard and lowercase header names
        const authHeader = event.headers.authorization || event.headers.Authorization;
        const { decoded: verifiedTokenPayload, token: userJwt } = await verifyToken(authHeader);
        const auth0UserId = verifiedTokenPayload.sub;
        console.log(`Token verified for sub: ${auth0UserId}, grant_type: ${verifiedTokenPayload.gty}`);

        // --- Create Request-Scoped Supabase Client --- 
        const userSupabase = createClient(supabaseUrl, supabaseAnonKey, {
            global: { headers: { Authorization: `Bearer ${userJwt}` } }
        });

        // --- API Route Handling --- 

        // GET /me - Fetch the customer profile
        if (method === 'GET' && subPath === '/me') {
            console.log(`Handling GET /me for auth0_user_id: ${auth0UserId}`);
            const { data: customer, error: dbError } = await userSupabase
                .from('customers')
                .select('*')
                .eq('auth0_user_id', auth0UserId)
                .single();
            if (dbError) {
                console.error('Supabase error fetching customer:', dbError);
                if (dbError.code === 'PGRST116') {
                    return createJsonResponse(404, { message: 'Customer profile not found for this user.' });
                } 
                return createJsonResponse(500, { message: 'Database error fetching customer profile.' });
            }
            if (!customer) { 
                 return createJsonResponse(404, { message: 'Customer profile not found for this user.' });
            }
            return createJsonResponse(200, customer);
        }
        // POST / - Create a new customer profile
        else if (method === 'POST' && subPath === '/') {
            console.log(`Handling POST / for auth0_user_id: ${auth0UserId}`);
            let requestBody = {};
            try {
                requestBody = JSON.parse(event.body || '{}');
            } catch (parseError) {
                return createJsonResponse(400, { message: 'Invalid JSON request body' });
            }
            if (!requestBody.full_name) { 
                return createJsonResponse(400, { message: 'Missing required field: full_name' });
            }
            if (!requestBody.email) {
                return createJsonResponse(400, { message: 'Missing required field: email' });
            }
            const customerData = {
                auth0_user_id: auth0UserId, 
                email: requestBody.email,
                full_name: requestBody.full_name || null, 
                date_of_birth: requestBody.date_of_birth || null,
                address: requestBody.address || null,
            };
            const { data: newCustomer, error: dbError } = await userSupabase
                .from('customers')
                .insert(customerData)
                .select() 
                .single(); 
            if (dbError) {
                console.error('Supabase error creating customer:', dbError);
                if (dbError.code === '23505') { 
                    let field = 'unknown field';
                    if (dbError.message.includes('customers_auth0_user_id_key')) field = 'auth0_user_id';
                    if (dbError.message.includes('customers_email_key')) field = 'email';
                    return createJsonResponse(409, { message: `Conflict: Customer with this ${field} already exists.` });
                }
                return createJsonResponse(500, { message: 'Database error creating customer profile.' });
            }
            return createJsonResponse(201, newCustomer);
        }
        // PATCH /me - Update existing customer profile
        /**
         * Handles PATCH requests to /me.
         * Updates the customer profile associated with the authenticated Auth0 user.
         * Accepts updates for full_name, date_of_birth (YYYY-MM-DD), and address (object).
         * Relies on RLS policy `update_own_customer`.
         * @param {string} event.body JSON string containing fields to update.
         * @returns {Promise<object>} Netlify response: 200 with updated customer data, 400 on bad input, 404 if not found, 500 on error.
         */
        else if (method === 'PATCH' && subPath === '/me') {
            console.log(`Handling PATCH /me for auth0_user_id: ${auth0UserId}`);
            let requestBody = {};
            try {
                requestBody = JSON.parse(event.body || '{}');
            } catch (parseError) {
                return createJsonResponse(400, { message: 'Invalid JSON request body' });
            }

            // Define updatable fields and validate
            const updates = {};
            if (requestBody.full_name !== undefined) updates.full_name = requestBody.full_name;
            if (requestBody.date_of_birth !== undefined) {
                // Basic validation: Check if it looks like YYYY-MM-DD
                if (!/^\d{4}-\d{2}-\d{2}$/.test(requestBody.date_of_birth)) {
                    return createJsonResponse(400, { message: 'Invalid date_of_birth format (YYYY-MM-DD required).' });
                }
                updates.date_of_birth = requestBody.date_of_birth;
            }
            if (requestBody.address !== undefined) {
                 // TODO: Add deeper validation for address object if needed
                 if (typeof requestBody.address !== 'object' || requestBody.address === null) {
                      return createJsonResponse(400, { message: 'Invalid address format (must be an object).' });
                 }
                updates.address = requestBody.address;
            }
            // Add other updatable fields here (e.g., nickname, phone)

            if (Object.keys(updates).length === 0) {
                return createJsonResponse(400, { message: 'No valid fields provided for update.' });
            }

            // Perform the update, relying on RLS policy 'update_own_customer'
            const { data: updatedCustomer, error: dbError } = await userSupabase
                .from('customers')
                .update(updates)
                .eq('auth0_user_id', auth0UserId)
                .select()
                .single();

            if (dbError) {
                console.error('Supabase error updating customer:', dbError);
                // If RLS prevents update (e.g., trying to update someone else - shouldn't happen with eq)
                // or if the user doesn't exist (PGRST116 might occur here if RLS passes but row gone)
                if (dbError.code === 'PGRST116') { 
                    return createJsonResponse(404, { message: 'Customer profile not found for update.' });
                }
                 // Handle potential unique constraint violations if email were updatable
                return createJsonResponse(500, { message: 'Database error updating customer profile.' });
            }

            // If RLS passed but no row was updated (e.g., concurrent delete)
             if (!updatedCustomer) {
                  return createJsonResponse(404, { message: 'Customer profile not found for update.' });
             }

            return createJsonResponse(200, updatedCustomer);
        }
        // DELETE /me - Delete existing customer profile
        /**
         * Handles DELETE requests to /me.
         * Deletes the customer profile associated with the authenticated Auth0 user.
         * Requires RLS policy `delete_own_customer` (or similar) to be defined and enabled.
         * @returns {Promise<object>} Netlify response: 204 on success, 404 if not found, 500 on error.
         */
        else if (method === 'DELETE' && subPath === '/me') {
            console.log(`Handling DELETE /me for auth0_user_id: ${auth0UserId}`);
            
            // Perform delete, relying on RLS policy 'delete_own_customer' (needs creation)
            const { error: dbError, count } = await userSupabase
                .from('customers')
                .delete()
                .eq('auth0_user_id', auth0UserId);

            if (dbError) {
                console.error('Supabase error deleting customer:', dbError);
                // RLS might prevent delete, resulting in an error or count=0
                // Treat RLS denial (if detectable) or other DB errors as 500 for now
                return createJsonResponse(500, { message: 'Database error deleting customer profile.' });
            }
            
            // Check if a row was actually deleted
            if (count === 0) {
                // This implies the user didn't exist or RLS prevented the delete
                 return createJsonResponse(404, { message: 'Customer profile not found for deletion.' });
            }

            console.log(`Successfully deleted customer profile for ${auth0UserId}`);
             // Return 204 No Content for successful deletion
            return { statusCode: 204 }; 
        }
        // Default: Route not found
        else {
            return createJsonResponse(404, { message: 'Function route not found' });
        }

    } catch (error) {
        // --- Centralized Error Handling --- 
        console.error('Function Error:', error);
        return createJsonResponse(
            error.statusCode || 500, 
            { message: error.message || 'Internal Server Error' }
        );
    }
}

/**
 * Public Netlify Function handler for Customer Service.
 * Acts as the main entry point, calling the internal logic handler.
 */
exports.handler = async (event, context) => {
    return handlerInternal(event, context);
};

// --- Exports for Testing --- 
module.exports = {
    handler: exports.handler,
    handlerInternal, // Export the internal handler
    verifyToken // Optionally export verifyToken if tests need to mock it specifically
}; 