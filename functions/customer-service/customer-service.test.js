// functions/customer-service/customer-service.test.js

// Reset modules to apply new mocks FIRST
jest.resetModules(); 

// --- Mock Environment Variables --- (Ensure these are defined BEFORE require)
process.env.SUPABASE_URL = 'http://mock-supabase.co';
process.env.SUPABASE_ANON_KEY = 'mock-anon-key';
// process.env.SUPABASE_SERVICE_ROLE_KEY = 'mock-service-role-key'; // Service role key not directly used by JWT flow logic being tested here
process.env.AUTH0_DOMAIN = 'mock-auth0-domain.com';
process.env.AUTH0_AUDIENCE = 'mock-audience';
process.env.SUPABASE_JWT_SECRET = 'mock-jwt-secret'; // Needed for Supabase client setup even if verifyToken is primary

// --- Mock External Dependencies ---

// Mock Supabase Client
const mockFrom = jest.fn();
// const mockSelect = jest.fn(); // Unused
// const mockEq = jest.fn(); // Unused
// const mockSingle = jest.fn(); // Unused
const mockInsert = jest.fn();
const mockSupabaseClient = {
    from: mockFrom,
    // Note: customer-service doesn't use rpc directly, only via createClient setup maybe
};
jest.mock('@supabase/supabase-js', () => ({ 
    createClient: jest.fn(() => mockSupabaseClient)
}));

// Mock JWT Libraries
const mockJwtVerify = jest.fn();
const mockGetSigningKey = jest.fn();
jest.mock('jsonwebtoken', () => ({
    verify: mockJwtVerify
}));
jest.mock('jwks-rsa', () => ({
    JwksClient: jest.fn(() => ({
        getSigningKey: mockGetSigningKey
    }))
}));

// --- Import Helpers ---
// const { createJsonResponse } = require('../utils/responseUtils.js'); // Unused

// --- Import Module Under Test ---
// Environment variables are set before this require runs
const customerServiceModule = require('./customer-service');
const handlerInternal = customerServiceModule.handlerInternal;
// We might need the actual implementation for specific mocks if needed, but usually test handlerInternal
// const verifyTokenImplementation = customerServiceModule.verifyTokenImplementation;

// Require mocked libraries AFTER jest.mock calls (not strictly necessary but good practice)
// const jwt = require('jsonwebtoken'); // Unused
// const { JwksClient } = require('jwks-rsa'); // Unused

// --- Define Mock Data ---
const mockCustomerId = 'cust-uuid-from-db-123';
const mockAuth0UserId = 'auth0|user-for-customer-tests';
const mockValidJwt = 'mockValidCustomerServiceToken';
const mockDecodedToken = { sub: mockAuth0UserId };
const mockEmail = 'test.customer@example.com';
const mockFullName = 'Test Customer Name';
const mockCustomerRecord = { // Represents a customer record from the DB
    id: mockCustomerId,
    auth0_user_id: mockAuth0UserId,
    email: mockEmail,
    full_name: mockFullName,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    status: 'PENDING_VERIFICATION',
    kyc_status: null,
    address: null,
    date_of_birth: null
};
const mockNewCustomerBody = { // Represents the body for creating a new customer
    email: mockEmail,
    full_name: mockFullName,
};

// --- Test Suite Setup ---
describe('Customer Service Handler (handlerInternal)', () => {

    // Reset mocks before each test
    beforeEach(() => {
        jest.clearAllMocks();

        // You might need to explicitly reset mocks that have complex implementations
        // set in helpers or tests, although clearAllMocks often suffices for basic resets.
        // e.g., mockFrom.mockImplementation(() => mockSupabaseClientInstance);
    });

    // --- Helper Functions ---

    const createMockEvent = (httpMethod, path, body = null, headers = {}) => {
         const baseHeaders = {
            'Content-Type': 'application/json',
            // Default to adding JWT header unless explicitly overridden or removed
            Authorization: `Bearer ${mockValidJwt}`,
            ...headers // Apply overrides
        };

        // Allow explicitly removing the Authorization header
        if (headers.Authorization === null) {
             delete baseHeaders.Authorization;
        }

        return {
            httpMethod,
            path,
            headers: baseHeaders,
            body: body ? ((typeof body === 'string') ? body : JSON.stringify(body)) : null,
            // customer-service doesn't use pathParameters
        };
    };

    // Mock failed JWT authentication
    const mockFailedJwtAuth = (error = new Error('Mock verification failure')) => {
        mockJwtVerify.mockImplementation((token, keyLookup, options, callback) => {
            // Simulate the callback pattern used by jsonwebtoken verify
            callback(error, null);
        });
        // Also mock getSigningKey for completeness in case keyLookup is called
        mockGetSigningKey.mockImplementation((header, callback) => {
             callback(null, 'mock-signing-key'); // Or error if testing key lookup failure
        });
    };

    // Mock successful JWT authentication AND the subsequent internal customer lookup
    const mockSuccessfulJwtAuth = (customerLookupResult = { data: null, error: null }) => {
        // 1. Mock jwt.verify to succeed by calling the callback with the decoded token
        mockJwtVerify.mockImplementation((token, keyLookupFunc, options, callback) => {
             // Simulate the call to getSigningKey (the keyLookupFunc)
             keyLookupFunc({ kid: 'mockKid' }, (keyErr /*, signingKey*/) => {
                  if (keyErr) {
                       // If getSigningKey provided an error, pass it to jwt.verify's callback
                       return callback(keyErr);
                  }
                  // Otherwise, simulate successful verification by passing null error and the decoded token
                  callback(null, mockDecodedToken);
             });
        });

        // 2. Mock the getSigningKey function (used as keyLookupFunc by jwt.verify)
        mockGetSigningKey.mockImplementation((header, callback) => {
            // Simulate successful key retrieval
            callback(null, { publicKey: 'mock-signing-key', rsaPublicKey: 'mock-signing-key' });
        });

        // 3. Mock the specific Supabase call chain for customer lookup AND insert
        const customerSingleMock = jest.fn().mockResolvedValue(customerLookupResult); // Mock for .single() after select/eq
        const customerEqMock = jest.fn(() => ({ single: customerSingleMock }));
        const customerSelectMock = jest.fn(() => ({ eq: customerEqMock }));
        
        // Define mocks for the insert chain separately
        const insertSingleMock = jest.fn(); // Mock for .single() after insert/select
        const insertSelectMock = jest.fn(() => ({ single: insertSingleMock })); // Mock for .select() after insert
        // We configure the actual mockInsert function (defined globally) here
        mockInsert.mockImplementation(() => ({ select: insertSelectMock })); 

        // Now, configure mockFrom to return the correct chain based on what the test needs
        mockFrom.mockImplementation((table) => {
            if (table === 'customers') {
                // This object now holds all possible first-level chained functions
                return { 
                    select: customerSelectMock, // For GET operations
                    insert: mockInsert // For POST operations
                    // eq and single are returned by select/insert mocks respectively
                };
            }
            // Default fallback for other tables
            return {
                 select: jest.fn().mockReturnThis(),
                 insert: jest.fn().mockReturnThis(), // Add insert here too? Maybe not needed.
                 eq: jest.fn().mockReturnThis(),
                 single: jest.fn().mockResolvedValue({ data: null, error: new Error('Unexpected table access')})
            };
        });
        
        // Return the mocks for insert chain so tests can set specific return values
        return { insertSingleMock }; 
    };

    // --- Test Suites ---

    describe('Authentication Errors', () => {
        test('should return 401 if Authorization header is missing', async () => {
            // Create event without the Authorization header
            const event = createMockEvent('GET', '/me', null, { Authorization: null });

            const response = await handlerInternal(event, {}); // Call handler

            // Assertions
            expect(response.statusCode).toBe(401);
            // Check the specific error message returned by the handler
            expect(JSON.parse(response.body).message).toBe('Missing or invalid Authorization header. Expected: Bearer <token>'); 
            // Ensure no JWT or DB operations were attempted
            expect(mockJwtVerify).not.toHaveBeenCalled();
            expect(mockFrom).not.toHaveBeenCalled();
        });

        test('should return 401 if JWT verification fails (e.g., bad signature)', async () => {
            const verificationError = new Error('invalid signature');
            mockFailedJwtAuth(verificationError); // Use helper to set up failure

            const event = createMockEvent('GET', '/me'); // Path doesn't matter much here
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(401); // Or 403 depending on specific error mapping
            // Match the specific error message format from verifyTokenImplementation
            expect(JSON.parse(response.body).message).toContain('Token verification failed: invalid signature'); 
            expect(mockJwtVerify).toHaveBeenCalledTimes(1);
            expect(mockFrom).not.toHaveBeenCalled(); // Database lookup shouldn't happen
        });

        // Add more specific auth errors? e.g., TokenExpiredError -> 403?
        // test('should return 403 if JWT is expired', async () => { ... });

    });

    describe('GET /me', () => {
        test('should return 200 and customer data if customer exists', async () => {
            // Mock successful auth AND the customer lookup succeeding
            mockSuccessfulJwtAuth({ data: mockCustomerRecord, error: null });

            const event = createMockEvent('GET', '/me');
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(mockCustomerRecord);
            // Verify the specific mocks involved
            expect(mockJwtVerify).toHaveBeenCalledTimes(1);
            // Check that the Supabase call was made correctly for GET /me
            expect(mockFrom).toHaveBeenCalledWith('customers');
            // The helper `mockSuccessfulJwtAuth` mocks the internal lookup.
            // The actual handler code for GET /me makes a separate call.
            // We need to refine the mock setup or assert based on the second call.
            // For now, let's assert it was called at least once.
            expect(mockFrom).toHaveBeenCalled(); 
            // TODO: Refine assertion to check select('*').eq(...).single() for GET /me
        });

        test('should return 404 if customer does not exist for the authenticated user', async () => {
            // Mock successful auth BUT the customer lookup failing
            mockSuccessfulJwtAuth({ data: null, error: null }); // Simulate no record found

            const event = createMockEvent('GET', '/me');
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body).message).toBe('Customer profile not found for this user.');
            expect(mockJwtVerify).toHaveBeenCalledTimes(1);
            // Check that the Supabase call was made
            expect(mockFrom).toHaveBeenCalledWith('customers');
             // TODO: Refine assertion as above
        });

        test('should return 500 if database error occurs during customer lookup', async () => {
            const dbError = { message: 'Database connection failed', code: 'DB500' };
            // Mock successful auth BUT the customer lookup returns a database error
            mockSuccessfulJwtAuth({ data: null, error: dbError });

            const event = createMockEvent('GET', '/me');
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(500);
            expect(JSON.parse(response.body).message).toBe('Database error fetching customer profile.');
            expect(mockJwtVerify).toHaveBeenCalledTimes(1);
            // Check that the Supabase call was made
            expect(mockFrom).toHaveBeenCalledWith('customers');
             // TODO: Refine assertion as above
        });
    });

    describe('POST /', () => {
        test('should create a new customer successfully', async () => {
            // Mock successful auth. The helper now returns mocks needed for POST.
            const { insertSingleMock } = mockSuccessfulJwtAuth({ data: null, error: { code: 'PGRST116' } }); // Simulate lookup fails

            // Mock the insert operation succeeding
            insertSingleMock.mockResolvedValueOnce({ data: mockCustomerRecord, error: null }); 

            const event = createMockEvent('POST', '/', mockNewCustomerBody);
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(201);
            expect(JSON.parse(response.body)).toEqual(mockCustomerRecord);
            expect(mockJwtVerify).toHaveBeenCalledTimes(1); 
            // Verify the insert call details
            expect(mockInsert).toHaveBeenCalledWith(expect.objectContaining({ 
                auth0_user_id: mockAuth0UserId, 
                email: mockEmail 
            }));
            expect(insertSingleMock).toHaveBeenCalledTimes(1);
        });

        test('should return 409 Conflict if customer already exists', async () => {
             // Mock successful auth. The helper now returns mocks needed for POST.
             const { insertSingleMock } = mockSuccessfulJwtAuth({ data: mockCustomerRecord, error: null }); // Lookup succeeds

             // Mock the insert failing with a 23505 error specifically for this test.
             const dbError = { code: '23505', message: 'duplicate key value violates unique constraint "customers_auth0_user_id_key"' };
             insertSingleMock.mockResolvedValueOnce({ data: null, error: dbError });

             const event = createMockEvent('POST', '/', mockNewCustomerBody);
             const response = await handlerInternal(event, {});

             expect(response.statusCode).toBe(409); 
             expect(JSON.parse(response.body).message).toBe('Conflict: Customer with this auth0_user_id already exists.');
             expect(mockJwtVerify).toHaveBeenCalledTimes(1); 
             expect(mockInsert).toHaveBeenCalledTimes(1); // Ensure insert was attempted
             expect(insertSingleMock).toHaveBeenCalledTimes(1);
        });

        test('should return 400 for missing email in request body', async () => {
            // No DB interaction expected, just need auth mock
            mockSuccessfulJwtAuth(); // Don't need insertSingleMock here
            const invalidBody = { ...mockNewCustomerBody };
            delete invalidBody.email;
            const event = createMockEvent('POST', '/', invalidBody);
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).message).toBe('Missing required field: email');
            expect(mockJwtVerify).toHaveBeenCalledTimes(1);
            expect(mockInsert).not.toHaveBeenCalled();
        });

        test('should return 400 for missing full_name in request body', async () => {
             // No DB interaction expected, just need auth mock
             mockSuccessfulJwtAuth(); // Don't need insertSingleMock here
             const invalidBody = { ...mockNewCustomerBody };
             delete invalidBody.full_name;
             const event = createMockEvent('POST', '/', invalidBody);
             const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(400);
             expect(JSON.parse(response.body).message).toBe('Missing required field: full_name');
             expect(mockJwtVerify).toHaveBeenCalledTimes(1);
             expect(mockInsert).not.toHaveBeenCalled();
        });
        
        test('should return 500 if database insert fails', async () => {
             // Mock successful auth. The helper now returns mocks needed for POST.
             const { insertSingleMock } = mockSuccessfulJwtAuth({ data: null, error: { code: 'PGRST116' } }); // Lookup fails
             const dbError = { message: 'Insert failed on purpose', code: 'DB_INSERT_FAIL' };
             // Mock the insert operation failing with a generic error
             insertSingleMock.mockResolvedValueOnce({ data: null, error: dbError });

             const event = createMockEvent('POST', '/', mockNewCustomerBody);
             const response = await handlerInternal(event, {});

             expect(response.statusCode).toBe(500);
             expect(JSON.parse(response.body).message).toBe('Database error creating customer profile.');
             expect(mockJwtVerify).toHaveBeenCalledTimes(1);
             expect(mockInsert).toHaveBeenCalledTimes(1);
             expect(insertSingleMock).toHaveBeenCalledTimes(1);
        });

         test('should return 409 if insert fails with unique constraint violation (23505)', async () => {
              // Mock successful auth. The helper now returns mocks needed for POST.
              const { insertSingleMock } = mockSuccessfulJwtAuth({ data: null, error: { code: 'PGRST116' } }); // Lookup fails
              const dbError = { code: '23505', message: 'duplicate key value violates unique constraint "customers_auth0_user_id_key"' };
              // Mock the insert operation failing with a 23505 error
              insertSingleMock.mockResolvedValueOnce({ data: null, error: dbError });

              const event = createMockEvent('POST', '/', mockNewCustomerBody);
              const response = await handlerInternal(event, {});

              expect(response.statusCode).toBe(409); 
              // Check the specific field identified in the error message if possible
              expect(JSON.parse(response.body).message).toContain('Conflict: Customer with this auth0_user_id already exists.');
              expect(mockJwtVerify).toHaveBeenCalledTimes(1);
              expect(mockInsert).toHaveBeenCalledTimes(1);
              expect(insertSingleMock).toHaveBeenCalledTimes(1);
        });
    });

    describe('Unknown Route / Method', () => {
        test('should return 404 for an unknown path', async () => {
            // Mock successful auth, as routing happens after auth
            mockSuccessfulJwtAuth({ data: null, error: null }); // Doesn't matter if customer exists

            const event = createMockEvent('GET', '/non-existent-path');
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body).message).toBe('Function route not found');
            expect(mockJwtVerify).toHaveBeenCalledTimes(1); 
            // Ensure no DB *action* (insert/update/delete) was attempted for unknown route
            expect(mockInsert).not.toHaveBeenCalled();
            // Note: mockFrom(customers) *is* called by mockSuccessfulJwtAuth helper
        });

        test('should return 404 for unsupported method on known path (/me)', async () => {
             // Mock successful auth
             mockSuccessfulJwtAuth({ data: mockCustomerRecord, error: null }); // Assume customer exists

             // Use PUT which is not supported for /me
             const event = createMockEvent('PUT', '/me'); 
             const response = await handlerInternal(event, {});

             expect(response.statusCode).toBe(404); // customer-service returns 404 for unsupported methods
             expect(JSON.parse(response.body).message).toBe('Function route not found'); 
             expect(mockJwtVerify).toHaveBeenCalledTimes(1);
             expect(mockInsert).not.toHaveBeenCalled(); 
             // GET /me logic might have been partially triggered depending on implementation,
             // but the final response should be 404.
         });

         test('should return 404 for unsupported method on known path (/)', async () => {
             // Mock successful auth
             mockSuccessfulJwtAuth({ data: null, error: null });

             // Use DELETE which is not supported for /
             const event = createMockEvent('DELETE', '/'); 
             const response = await handlerInternal(event, {});

             expect(response.statusCode).toBe(404);
             expect(JSON.parse(response.body).message).toBe('Function route not found');
             expect(mockJwtVerify).toHaveBeenCalledTimes(1);
             expect(mockInsert).not.toHaveBeenCalled();
        });
    });

}); // End describe suite 