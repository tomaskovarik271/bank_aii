// functions/account-service/account-service.test.js

// --- Mock Environment Variables --- (Ensure these are defined BEFORE require)
process.env.SUPABASE_URL = 'http://mock-supabase.co';
process.env.SUPABASE_ANON_KEY = 'mock-anon-key';
process.env.SUPABASE_JWT_SECRET = 'mock-jwt-secret';
process.env.AUTH0_DOMAIN = 'mock-auth0-domain.com';
process.env.AUTH0_AUDIENCE = 'mock-audience';

// Helper function to create a JSON response object (matching Netlify/AWS format)
/* // Comment out unused function for now
const createJsonResponse = (statusCode, body) => ({
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
});
*/

// --- Mock External Dependencies ---

// --- Mock Supabase Client ---
const mockFrom = jest.fn();
const mockRpc = jest.fn();
const mockSupabaseClient = { 
    from: mockFrom,
    rpc: mockRpc,
};

jest.mock('@supabase/supabase-js', () => ({
    createClient: jest.fn(() => mockSupabaseClient) // Always return the same base mock client
}));

// --- Mock JWT Libraries --- 
jest.mock('jsonwebtoken'); 
jest.mock('jwks-rsa');

// --- Mock Internal Auth Functions ---
// This is the mock function that will be INJECTED into the handler during tests
const mockGetCustomerIdForApiKey = jest.fn();

// --- Mock crypto ---
const mockRandomUUID = jest.fn();
jest.mock('crypto', () => ({
    ...jest.requireActual('crypto'),
    randomUUID: mockRandomUUID
}));

// --- Import Module Under Test --- 
// Environment variables are set before this require runs
const accountServiceModule = require('./account-service');
const handlerInternal = accountServiceModule.handlerInternal; 
// We don't typically need to import the actual implementations we are mocking/injecting
// const getCustomerIdForApiKeyImplementation = accountServiceModule.getCustomerIdForApiKey; 

// Require mocked libraries AFTER jest.mock calls
const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');

// --- Test Suite ---
describe('Account Service Handler (handlerInternal)', () => {
    const mockCustomerId = 'cust-uuid-111aaa'; // Use UUID format
    const mockAuth0UserId = 'auth0|user-for-accounts';
    const mockValidJwt = 'mockValidTokenString';
    const mockDecodedToken = { sub: mockAuth0UserId };
    const mockApiKey = 'test-api-key-xyz';
    const mockGeneratedUUID = 'uuid-generated-by-crypto';
    const mockGeneratedAccountNumber = mockGeneratedUUID;
    const mockAccountId = '550e8400-e29b-41d4-a716-446655440000'; // Use standard UUID
    const mockAccountId2 = '123e4567-e89b-12d3-a456-426614174000'; // Another valid UUID for distinction
    const mockInvalidAccountId = 'not-a-uuid-format';
    const mockCreatedAt = new Date().toISOString();
    const expectedReturnedAccountBase = { 
        id: mockAccountId, // Consistent ID
            customer_id: mockCustomerId,
        account_number: mockGeneratedAccountNumber,
            account_type: 'CHECKING',
            currency: 'USD',
        nickname: 'My Main Checking',
        created_at: mockCreatedAt,
        updated_at: mockCreatedAt,
        is_active: true
     }; // Balance added dynamically via RPC mock

    // Define mock implementations reusable in helpers/tests
    // const mockGetSigningKey = jest.fn(); // Unused

    // Helper to create mock event (mostly unchanged)
    const createMockEvent = (httpMethod, path, body = null, headers = {}, pathParameters = null) => {
         const baseHeaders = {
            'Content-Type': 'application/json',
            ...headers
        };
        // Determine which auth header to add by default based on explicit settings
        if (headers.Authorization === undefined && headers['x-api-key'] === undefined) {
             // Default to JWT if nothing else specified
             baseHeaders.Authorization = `Bearer ${mockValidJwt}`;
        } else if (headers.Authorization === null) {
             delete baseHeaders.Authorization; // Allow explicitly removing JWT
        }

        if (headers['x-api-key'] === null) {
             delete baseHeaders['x-api-key']; // Allow explicitly removing API key
        }
        // Don't add API key by default, let tests add it via headers

        return {
            httpMethod,
            path,
            headers: baseHeaders,
            body: body ? ((typeof body === 'string') ? body : JSON.stringify(body)) : null,
            pathParameters
        };
    };

    // Helper for successful JWT auth mock setup (Needs modification for new strategy)
    const mockSuccessfulJwtAuth = (customerId = mockCustomerId) => {
        // Configure JWT mocks (jsonwebtoken, jwks-rsa)
        const mockGetSigningKeyFunc = jest.fn((header, callback) => { callback(null, 'mock-signing-key'); }); // Renamed variable
        JwksClient.mockImplementation(() => ({ getSigningKey: mockGetSigningKeyFunc }));
        jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
            callback(null, mockDecodedToken);
        });

        // Mock the customer lookup: from('customers').select('id').eq('auth0_user_id', ...).single()
        // Note: We configure this directly here now, not relying on beforeEach defaults.
        mockFrom.mockImplementationOnce((table) => {
             if (table === 'customers') {
                 return { 
                     select: jest.fn().mockReturnThis(), // select returns 'this' for chaining
                     eq: jest.fn().mockReturnThis(),      // eq returns 'this'
                     single: jest.fn().mockResolvedValueOnce({ data: { id: customerId }, error: null })
                 };
             }
             return {}; // Return empty object for other tables in this specific mock setup
         });
    };

    const mockSuccessfulApiKeyAuth = (customerId = mockCustomerId) => {
        // Mock the function that gets injected
        mockGetCustomerIdForApiKey.mockResolvedValue(customerId); 
    };

    const mockFailedApiKeyAuth = (errorToThrow) => {
        // Mock the function that gets injected
        mockGetCustomerIdForApiKey.mockRejectedValue(errorToThrow); 
    };

    // Reset mocks before each test
    beforeEach(() => {
        // Clear ALL mocks
        jest.clearAllMocks();

        // Reset the core Supabase client mocks
        mockFrom.mockReset();
        mockRpc.mockReset().mockResolvedValue({ data: null, error: null }); // Default RPC success
        
        // Setup the DEFAULT mock for the injected API Key function
        // Use the mock function variable, not the original implementation
        mockGetCustomerIdForApiKey.mockResolvedValue('default-api-key-customer-id'); 
    });

    // == POST /accounts ==
    describe('POST /accounts', () => {
        const newAccountDataBase = { account_type: 'Checking', currency: 'USD', nickname: 'My Main Checking' };
        const expectedNewAccount = { 
            ...expectedReturnedAccountBase, 
            id: mockAccountId, 
            account_type: 'CHECKING', 
            nickname: 'My Main Checking'
        }; // Simplified expected without balance

        test('should create a new account successfully (JWT Auth)', async () => {
            mockSuccessfulJwtAuth(); // Sets up JWT + customer lookup mock
            mockRandomUUID.mockReturnValueOnce(mockGeneratedUUID);
            
            // Mock: from('accounts').insert(...).select().single()
            const insertSingleMock = jest.fn().mockResolvedValueOnce({ data: expectedNewAccount, error: null });
            const insertSelectMock = jest.fn(() => ({ single: insertSingleMock }));
            const insertMock = jest.fn(() => ({ select: insertSelectMock }));
            // Configure mockFrom *after* mockSuccessfulJwtAuth (which already mocked 'customers')
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { insert: insertMock };
                return {}; // Fallback for any unexpected table
            });

            const event = createMockEvent('POST', '/accounts', newAccountDataBase);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(201);
            const responseBody = JSON.parse(response.body);
            expect(responseBody.id).toBe(mockAccountId);
            expect(insertMock).toHaveBeenCalledWith(expect.objectContaining({ customer_id: mockCustomerId }));
        });
        
        test('should return 401 if Authorization header is missing', async () => {
             const event = createMockEvent('POST', '/accounts', newAccountDataBase, { Authorization: null }); // Explicitly remove auth header
             // Running the handler with the *actual* implementation of verifyToken 
             const response = await handlerInternal(event, {});
             expect(response.statusCode).toBe(401);
             expect(JSON.parse(response.body).message).toBe('Authentication required.');
        });

         test('should return 401 if JWT verification fails (mock rejects)', async () => {
             // Mock jsonwebtoken.verify to call its callback with an error
             jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
                 callback(new Error('Mock verification fail'), null); 
             });

             const event = createMockEvent('POST', '/accounts', newAccountDataBase);
             const response = await handlerInternal(event, {});

             expect(response.statusCode).toBe(401);
             expect(JSON.parse(response.body).message).toContain('Token verification failed');
             expect(jwt.verify).toHaveBeenCalledTimes(1);
         });

         test('should return 403 if customer lookup fails after successful JWT verification', async () => {
             // Mock JWT success first
             const mockGetSigningKeyFunc = jest.fn((header, callback) => { callback(null, 'mock-signing-key'); });
             JwksClient.mockImplementation(() => ({ getSigningKey: mockGetSigningKeyFunc }));
             jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
                 callback(null, mockDecodedToken);
             });

             // OVERRIDE the customer lookup part to fail
             mockFrom.mockImplementationOnce(table => {
                 if (table === 'customers') {
                     // Simulate Supabase error when customer not found via RLS/query
                     const customerSingleMock = jest.fn().mockResolvedValue({ data: null, error: { message: 'RLS error or not found'} });
                     const customerEqMock = jest.fn(() => ({ single: customerSingleMock }));
                     const customerSelectMock = jest.fn(() => ({ eq: customerEqMock }));
                     return { select: customerSelectMock };
                 }
                 return {}; // Should not be reached
             });

             const event = createMockEvent('POST', '/accounts', newAccountDataBase);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(403);
             expect(JSON.parse(response.body).message).toBe('Forbidden: Customer profile required.');
             expect(jwt.verify).toHaveBeenCalledTimes(1); // Ensure auth was attempted
             expect(mockFrom).toHaveBeenCalledWith('customers'); // Ensure DB lookup was attempted
         });

        test('should return 400 for invalid account type', async () => {
             mockSuccessfulJwtAuth(); 
             const event = createMockEvent('POST', '/accounts', { ...newAccountDataBase, account_type: 'INVALID' });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey); 
            expect(response.statusCode).toBe(400);
             expect(JSON.parse(response.body).message).toContain('account_type (CHECKING or SAVINGS)');
         });

         test('should return 400 for missing required field (currency)', async () => {
             mockSuccessfulJwtAuth(); 
             const event = createMockEvent('POST', '/accounts', { ...newAccountDataBase, currency: undefined });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey); 
             expect(response.statusCode).toBe(400);
             expect(JSON.parse(response.body).message).toContain('currency (must be 3 characters)');
         });

         test('should return 500 if database insert fails', async () => {
             mockSuccessfulJwtAuth();
             mockRandomUUID.mockReturnValueOnce(mockGeneratedUUID);
             const dbError = { message: 'Insert failed', code: 'DB_ERR' };
             
             // Mock: from('accounts').insert(...).select().single() -> Error
             const insertSingleMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
             const insertSelectMock = jest.fn(() => ({ single: insertSingleMock }));
             const insertMock = jest.fn(() => ({ select: insertSelectMock }));
             mockFrom.mockImplementationOnce((table) => {
                 if (table === 'accounts') return { insert: insertMock };
                 return {};
             });

             const event = createMockEvent('POST', '/accounts', newAccountDataBase);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(500);
             expect(JSON.parse(response.body).message).toBe('Database error creating account.');
             expect(insertMock).toHaveBeenCalled();
         });
         
        test('should create a new account successfully (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth(); 
            mockRandomUUID.mockReturnValueOnce(mockGeneratedUUID);
            const mockReturnedAccount = { ...expectedReturnedAccountBase, account_type: 'SAVINGS' };
            
            // Mock: from('accounts').insert(...).select().single()
            const insertSingleMock = jest.fn().mockResolvedValueOnce({ data: mockReturnedAccount, error: null });
            const insertSelectMock = jest.fn(() => ({ single: insertSingleMock }));
            const insertMock = jest.fn(() => ({ select: insertSelectMock }));
            mockFrom.mockReturnValueOnce({ insert: insertMock }); // No customer lookup needed here

            const event = createMockEvent('POST', '/accounts', 
                { ...newAccountDataBase, account_type: 'SAVINGS' }, 
                { 'x-api-key': mockApiKey, Authorization: null }
            );
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(201); 
            expect(mockGetCustomerIdForApiKey).toHaveBeenCalledWith(mockApiKey, expect.any(Object));
            expect(insertMock).toHaveBeenCalledWith(expect.objectContaining({ account_type: 'SAVINGS' }));
            expect(JSON.parse(response.body)).toEqual(mockReturnedAccount);
        });
         
        test('should return 403 if API Key auth fails (mock rejects with 403)', async () => {
              const apiKeyError = { statusCode: 403, message: 'Invalid Key' };
              mockFailedApiKeyAuth(apiKeyError); 
              const event = createMockEvent('POST', '/accounts', newAccountDataBase, { Authorization: null, 'x-api-key': mockApiKey });
              const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
              expect(response.statusCode).toBe(403);
              expect(JSON.parse(response.body)).toEqual({ message: 'Invalid Key' });
              expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
          });
          
         test('should return 500 if API Key auth fails (mock rejects with 500)', async () => {
              const apiKeyError = { statusCode: 500, message: 'DB error during key check' };
              mockFailedApiKeyAuth(apiKeyError); 
              const event = createMockEvent('POST', '/accounts', newAccountDataBase, { Authorization: null, 'x-api-key': mockApiKey });
              const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
              expect(response.statusCode).toBe(500);
              // Adjust assertion for centralized error handler
              expect(JSON.parse(response.body)).toEqual({ 
                  message: 'Internal Server Error', // Generic message
                  error: 'DB error during key check'  // Specific error
              });
              expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
          });

         test('should return 400 for invalid body with API Key Auth', async () => {
             mockSuccessfulApiKeyAuth(); 
             // No need to mock DB calls as validation should fail first
             const event = createMockEvent('POST', '/accounts', { nickname: 'No type' }, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(400);
             expect(JSON.parse(response.body).message).toContain('account_type (CHECKING or SAVINGS)');
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1); 
             expect(mockFrom).not.toHaveBeenCalled(); // Assert DB call wasn't made
         });
    });

    // == GET /accounts ==
    describe('GET /accounts', () => {
        test('should return list of accounts successfully (JWT Auth)', async () => {
            mockSuccessfulJwtAuth(); // Sets up JWT + customer lookup mock
            const mockAccountsList = [expectedReturnedAccountBase];
            
            // Mock: from('accounts').select('*').eq('customer_id', ...)
            // .eq() resolves directly for list results
            const eqMock = jest.fn().mockResolvedValueOnce({ data: mockAccountsList, error: null });
            const selectMock = jest.fn(() => ({ eq: eqMock }));
            // Configure mockFrom *after* mockSuccessfulJwtAuth
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { select: selectMock };
                return {}; // Fallback for customer table called by mockSuccessfulJwtAuth
            });

            const event = createMockEvent('GET', '/accounts');
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
            
            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(mockAccountsList);
            expect(mockFrom).toHaveBeenCalledWith('accounts');
            expect(selectMock).toHaveBeenCalledWith('*');
            expect(eqMock).toHaveBeenCalledWith('customer_id', mockCustomerId);
        });

        test('should return empty array if no accounts found (JWT Auth)', async () => {
            mockSuccessfulJwtAuth(); 
            
            // Mock: from('accounts').select('*').eq('customer_id', ...) -> Empty Array
            const eqMock = jest.fn().mockResolvedValueOnce({ data: [], error: null });
            const selectMock = jest.fn(() => ({ eq: eqMock }));
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { select: selectMock };
                return {};
            });

            const event = createMockEvent('GET', '/accounts');
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey); 
            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual([]);
            expect(eqMock).toHaveBeenCalledWith('customer_id', mockCustomerId);
        });

        test('should return 500 if database select fails (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const dbError = { message: 'Select failed', code: 'DB_ERR' };

            // Mock: from('accounts').select('*').eq('customer_id', ...) -> Error
            const eqMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
            const selectMock = jest.fn(() => ({ eq: eqMock }));
             mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { select: selectMock };
                return {};
            });

            const event = createMockEvent('GET', '/accounts');
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey); 
            expect(response.statusCode).toBe(500);
            expect(JSON.parse(response.body)).toEqual({ message: 'Database error fetching accounts.' });
            expect(eqMock).toHaveBeenCalledWith('customer_id', mockCustomerId);
        });
         
         // --- API Key Tests ---
         test('should return list of accounts successfully (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const mockAccountList = [{ ...expectedReturnedAccountBase, nickname: 'API Key Account' }];

             // Mock: from('accounts').select('*').eq('customer_id', ...)
             const eqMock = jest.fn().mockResolvedValueOnce({ data: mockAccountList, error: null });
             const selectMock = jest.fn(() => ({ eq: eqMock }));
             mockFrom.mockReturnValueOnce({ select: selectMock }); // No customer lookup needed
             
             const event = createMockEvent('GET', '/accounts', null, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             
             expect(response.statusCode).toBe(200);
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
             expect(mockFrom).toHaveBeenCalledWith('accounts');
             expect(eqMock).toHaveBeenCalledWith('customer_id', mockCustomerId);
             expect(JSON.parse(response.body)).toEqual(mockAccountList);
         });

         test('should return 500 if database select fails (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const dbError = { message: 'Select failed during API Key flow', code: 'DB_ERR_AK' };

             // Mock: from('accounts').select('*').eq('customer_id', ...) -> Error
             const eqMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
             const selectMock = jest.fn(() => ({ eq: eqMock }));
             mockFrom.mockReturnValueOnce({ select: selectMock });

             const event = createMockEvent('GET', '/accounts', null, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(500);
             expect(JSON.parse(response.body)).toEqual({ message: 'Database error fetching accounts.'}); 
             expect(eqMock).toHaveBeenCalledWith('customer_id', mockCustomerId);
         });
    });

     // == GET /accounts/{id} ==
     describe('GET /accounts/{id}', () => {
         test('should return a specific account successfully (JWT Auth)', async () => {
             mockSuccessfulJwtAuth(); // Sets up JWT + customer lookup mock
             const targetAccountId = mockAccountId;
             const mockAccountData = { ...expectedReturnedAccountBase };
             const mockBalance = 123.45;
             const mockAccountWithBalance = { ...mockAccountData, balance: mockBalance };

             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null }); 
             // Mock 2: from('accounts').select('*').eq('id', ...).single()
             const singleMock = jest.fn().mockResolvedValueOnce({ data: mockAccountData, error: null });
             const eqMock = jest.fn(() => ({ single: singleMock }));
             const selectMock = jest.fn(() => ({ eq: eqMock }));
              // Configure mockFrom *after* mockSuccessfulJwtAuth
             mockFrom.mockImplementationOnce((table) => {
                 if (table === 'accounts') return { select: selectMock };
                 return {}; // Fallback for customer table
             });
             // Mock 3: RPC calculate_balance (success -> balance)
             mockRpc.mockResolvedValueOnce({ data: mockBalance, error: null });
             
             const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(200);
             expect(JSON.parse(response.body)).toEqual(mockAccountWithBalance);
             expect(mockRpc).toHaveBeenNthCalledWith(1, 'check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
             expect(mockFrom).toHaveBeenCalledWith('accounts');
             expect(eqMock).toHaveBeenCalledWith('id', targetAccountId);
             expect(singleMock).toHaveBeenCalledTimes(1);
             expect(mockRpc).toHaveBeenNthCalledWith(2, 'calculate_balance', { p_account_id: targetAccountId });
             expect(mockRpc).toHaveBeenCalledTimes(2);
         });

         test('should return 404 if access check passes but final select returns null (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             const targetAccountId = mockAccountId;
             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             // Mock 2: from('accounts').select('*').eq('id', ...).single() -> Not Found (returns error PGRST116)
             const singleMock = jest.fn().mockResolvedValueOnce({ data: null, error: { code: 'PGRST116', message: 'Row not found'} }); // Simulate not found more accurately
             const eqMock = jest.fn(() => ({ single: singleMock }));
             const selectMock = jest.fn(() => ({ eq: eqMock }));
             mockFrom.mockImplementationOnce((table) => {
                 if (table === 'accounts') return { select: selectMock };
                 return {};
             });
             // Mock 3: calculate_balance RPC should NOT be called

             const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(404); // Correct expectation
             expect(JSON.parse(response.body)).toEqual({ message: 'Account not found or access denied.'});
             expect(mockRpc).toHaveBeenCalledTimes(1); // Only access check RPC
             expect(singleMock).toHaveBeenCalledTimes(1); // Select was attempted
         });

        test('should return 404 if final account select fails with other error (JWT Auth)', async () => { // Renamed test slightly
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            const dbError = { message: 'Some select error', code: 'XXYYZ' };
            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').select('*').eq('id', ...).single() -> Error
            const singleMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
            const eqMock = jest.fn(() => ({ single: singleMock }));
            const selectMock = jest.fn(() => ({ eq: eqMock }));
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { select: selectMock };
                return {};
            });
            // Mock 3: calculate_balance RPC should NOT be called

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            // The code currently returns 404 in this scenario (after access check succeeds but select fails)
            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body)).toEqual({ message: 'Account not found or access denied.'});
            expect(mockRpc).toHaveBeenCalledTimes(1);
            expect(singleMock).toHaveBeenCalledTimes(1);
        });

        test('should return 404 if check_account_access RPC returns false (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            // Mock 1: RPC check_account_access (fail -> false)
            mockRpc.mockResolvedValueOnce({ data: false, error: null });
            // Mock 2 & 3: DB select and balance RPC should NOT be called

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body)).toEqual({ message: 'Account not found or access denied.'});
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(mockRpc).toHaveBeenCalledTimes(1);
            expect(mockFrom).not.toHaveBeenCalledWith('accounts'); // Ensure select wasn't called
        });

        test('should return 500 if check_account_access RPC fails (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            const rpcError = { message: 'RPC check failed', code: 'RPC_ERR' };
            // Mock 1: RPC check_account_access (fail -> error)
            mockRpc.mockRejectedValueOnce(rpcError); // Simulate RPC throwing an error

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(500);
            // Expect generic message + specific error property
            expect(JSON.parse(response.body)).toEqual({
                 message: 'Internal Server Error', // Generic message
                 error: 'RPC check failed' // Specific error details
             });
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(mockRpc).toHaveBeenCalledTimes(1);
            expect(mockFrom).not.toHaveBeenCalledWith('accounts');
        });

        test('should return 500 if calculate_balance RPC fails (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            const mockAccountData = { ...expectedReturnedAccountBase };
            const rpcError = { message: 'Balance calculation error', code: 'BAL_ERR' };

            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').select('*').eq('id', ...).single() -> Success
            const singleMock = jest.fn().mockResolvedValueOnce({ data: mockAccountData, error: null });
            const eqMock = jest.fn(() => ({ single: singleMock }));
            const selectMock = jest.fn(() => ({ eq: eqMock }));
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { select: selectMock };
                return {};
            });
            // Mock 3: RPC calculate_balance (fail -> error)
            mockRpc.mockRejectedValueOnce(rpcError); 

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(500); 
            // Expect generic message + specific error property
            expect(JSON.parse(response.body)).toEqual({
                 message: 'Internal Server Error', // Generic message
                 error: 'Balance calculation error' // Specific error details
             });
            expect(mockRpc).toHaveBeenCalledTimes(2); // Both RPCs called
        });

        test('should return 400 for invalid account ID format (JWT Auth)', async () => {
            mockSuccessfulJwtAuth(); // Still need auth to happen before format check
            const invalidId = mockInvalidAccountId;
            const event = createMockEvent('GET', `/accounts/${invalidId}`);

            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(400); // Expect 400 for bad format
            expect(JSON.parse(response.body)).toEqual({ message: 'Invalid Account ID format.' });
            expect(mockRpc).not.toHaveBeenCalled(); // Access check should not happen
        });

        // --- API Key Tests ---
        test('should return a specific account successfully (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth();
            const targetAccountId = mockAccountId2; // Use a different ID for clarity
            const mockAccountData = { ...expectedReturnedAccountBase, id: targetAccountId };
            const mockBalance = 99.00;
            const mockAccountWithBalance = { ...mockAccountData, balance: mockBalance };

            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').select('*').eq('id', ...).single()
            const singleMock = jest.fn().mockResolvedValueOnce({ data: mockAccountData, error: null });
            const eqMock = jest.fn(() => ({ single: singleMock }));
            const selectMock = jest.fn(() => ({ eq: eqMock }));
            mockFrom.mockReturnValueOnce({ select: selectMock }); // No customer lookup needed for mockFrom
            // Mock 3: RPC calculate_balance (success -> balance)
            mockRpc.mockResolvedValueOnce({ data: mockBalance, error: null });

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`, null, { Authorization: null, 'x-api-key': mockApiKey });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(mockAccountWithBalance);
            expect(mockRpc).toHaveBeenNthCalledWith(1, 'check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(mockRpc).toHaveBeenNthCalledWith(2, 'calculate_balance', { p_account_id: targetAccountId });
            expect(mockRpc).toHaveBeenCalledTimes(2);
            expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
        });

        test('should return 404 if check_account_access RPC returns false (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth();
            const targetAccountId = mockAccountId;
            // Mock 1: RPC check_account_access (fail -> false)
            mockRpc.mockResolvedValueOnce({ data: false, error: null });
            // Mock 2 & 3: Should not be called

            const event = createMockEvent('GET', `/accounts/${targetAccountId}`, null, { Authorization: null, 'x-api-key': mockApiKey });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body)).toEqual({ message: 'Account not found or access denied.'});
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
            expect(mockFrom).not.toHaveBeenCalledWith('accounts');
        });

        test('should return 400 for invalid account ID format (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const invalidId = mockInvalidAccountId;
             const event = createMockEvent('GET', `/accounts/${invalidId}`, null, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(400); // Expect 400
             expect(JSON.parse(response.body)).toEqual({ message: 'Invalid Account ID format.' });
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1); // API Key check happens
             expect(mockRpc).not.toHaveBeenCalled(); // Access check should not
         });
    });

    // == POST /accounts/{accountId}/transactions == (Currently returns 501)
    describe('POST /accounts/{accountId}/transactions', () => {
        test('should return 501 Not Implemented (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            // Mock access check success
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            const event = createMockEvent('POST', `/accounts/${mockAccountId}/transactions`, { amount: 100 });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
            expect(response.statusCode).toBe(501);
            expect(JSON.parse(response.body)).toEqual({ message: 'Transaction creation not implemented yet.'});
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: mockAccountId, p_customer_id: mockCustomerId });
        });

        test('should return 404 if access check fails (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             // Mock access check failure
             mockRpc.mockResolvedValueOnce({ data: false, error: null });
             const event = createMockEvent('POST', `/accounts/${mockAccountId}/transactions`, { amount: 100 });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(404);
             expect(JSON.parse(response.body)).toEqual({ message: 'Account not found or access denied.' });
             expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: mockAccountId, p_customer_id: mockCustomerId });
         });

        test('should return 400 for invalid account ID format (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             const event = createMockEvent('POST', `/accounts/${mockInvalidAccountId}/transactions`, { amount: 100 });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(400);
             expect(JSON.parse(response.body)).toEqual({ message: 'Invalid Account ID format.' });
             expect(mockRpc).not.toHaveBeenCalled();
         });

         // API Key tests
         test('should return 501 Not Implemented (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             const event = createMockEvent('POST', `/accounts/${mockAccountId}/transactions`, { amount: 100 }, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(501);
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
             expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: mockAccountId, p_customer_id: mockCustomerId });
         });

         test('should return 404 if access check fails (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             mockRpc.mockResolvedValueOnce({ data: false, error: null });
             const event = createMockEvent('POST', `/accounts/${mockAccountId}/transactions`, { amount: 100 }, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(404);
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
             expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: mockAccountId, p_customer_id: mockCustomerId });
         });

          test('should return 400 for invalid account ID format (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const event = createMockEvent('POST', `/accounts/${mockInvalidAccountId}/transactions`, { amount: 100 }, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(400);
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
             expect(mockRpc).not.toHaveBeenCalled();
         });
    });

    // == GET /accounts/{accountId}/transactions ==
    describe('GET /accounts/{accountId}/transactions', () => {
        const mockTransactions = [
            { id: 1, transaction_id: 'tx-uuid-1', account_id: mockAccountId, entry_type: 'DEBIT', amount: 50.00, currency: 'USD', created_at: '2024-01-15T10:00:00Z', description: 'Payment' },
            { id: 2, transaction_id: 'tx-uuid-2', account_id: mockAccountId, entry_type: 'CREDIT', amount: 100.00, currency: 'USD', created_at: '2024-01-16T11:30:00Z', description: 'Deposit' }
        ];

        test('should return transactions successfully (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();

            // Mock check_account_access RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });

            // Mock get_account_transactions RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: mockTransactions, error: null });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(mockTransactions);
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', {
                p_account_id: mockAccountId,
                p_requesting_customer_id: mockCustomerId
            });
            expect(mockRpc).toHaveBeenCalledWith('get_account_transactions', {
                p_account_id: mockAccountId,
                p_requesting_customer_id: mockCustomerId
            });
        });

        test('should return transactions successfully (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth();

            // Mock check_account_access RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });

            // Mock get_account_transactions RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: mockTransactions, error: null });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`, null, { 'x-api-key': mockApiKey, Authorization: null });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(mockTransactions);
            expect(mockGetCustomerIdForApiKey).toHaveBeenCalledWith(mockApiKey, expect.anything());
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', {
                p_account_id: mockAccountId,
                p_requesting_customer_id: mockCustomerId // customerId from API key lookup
            });
            expect(mockRpc).toHaveBeenCalledWith('get_account_transactions', {
                p_account_id: mockAccountId,
                p_requesting_customer_id: mockCustomerId
            });
        });

        test('should return 403 if check_account_access RPC denies permission', async () => {
            mockSuccessfulJwtAuth();

            // Mock check_account_access RPC (Permission Denied)
            mockRpc.mockResolvedValueOnce({ 
                data: null, 
                error: { code: 'PGRST', message: 'Permission denied accessing account' }
            });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(403);
            expect(JSON.parse(response.body).message).toContain('Forbidden: You do not have access to this account.');
            expect(mockRpc).toHaveBeenCalledTimes(1); // Only check_account_access should be called
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', expect.anything());
        });

        test('should return 404 if get_account_transactions RPC indicates account not found', async () => {
            mockSuccessfulJwtAuth();

            // Mock check_account_access RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });

            // Mock get_account_transactions RPC (Account Not Found - PGRST116)
            mockRpc.mockResolvedValueOnce({ 
                data: null, 
                error: { code: 'PGRST116', message: 'Row not found' } 
            });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body).message).toContain(`Account not found: ${mockAccountId}`);
            expect(mockRpc).toHaveBeenCalledTimes(2); // Both RPCs called
        });

        test('should return 500 if check_account_access RPC fails with database error', async () => {
            mockSuccessfulJwtAuth();

            // Mock check_account_access RPC (DB Error)
            mockRpc.mockResolvedValueOnce({ 
                data: null, 
                error: { message: 'Generic DB error' } 
            });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(500);
            expect(JSON.parse(response.body).message).toContain('Database error during access check.');
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 500 if get_account_transactions RPC fails with database error', async () => {
            mockSuccessfulJwtAuth();

            // Mock check_account_access RPC (Success)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });

            // Mock get_account_transactions RPC (DB Error)
            mockRpc.mockResolvedValueOnce({ 
                data: null, 
                error: { message: 'Some other transaction fetch error' } 
            });

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(500);
            expect(JSON.parse(response.body).message).toContain('Error retrieving transactions.');
            expect(mockRpc).toHaveBeenCalledTimes(2); // Both RPCs called
        });

        test('should return 400 for invalid account ID format in path', async () => {
            mockSuccessfulJwtAuth(); // Auth needs to pass to reach ID validation

            const event = createMockEvent('GET', `/accounts/${mockInvalidAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).message).toBe('Invalid Account ID format.');
            expect(mockRpc).not.toHaveBeenCalled(); // Should fail before RPC calls
        });

        test('should return 401 if no authentication is provided', async () => {
            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`, null, { Authorization: null, 'x-api-key': null });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(401);
            expect(JSON.parse(response.body).message).toBe('Authentication required.');
        });

         test('should return 200 with empty array if no transactions exist', async () => {
            mockSuccessfulJwtAuth();
            mockRpc.mockResolvedValueOnce({ data: true, error: null }); // check_account_access
            mockRpc.mockResolvedValueOnce({ data: [], error: null }); // get_account_transactions returns empty

            const event = createMockEvent('GET', `/accounts/${mockAccountId}/transactions`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual([]);
        });
    });

    // == General Routing / Method Not Allowed ==
    describe('General Routing and Method Not Allowed', () => {
        test('should return 404 for completely unknown route (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const event = createMockEvent('GET', '/unknown/resource/path');
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body)).toEqual({ message: 'Function route not found' });
        });

        test('should return 405 for valid route with unsupported method (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const event = createMockEvent('PUT', '/accounts'); // PUT is not allowed on /accounts
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
            expect(response.statusCode).toBe(405);
            expect(JSON.parse(response.body)).toEqual({ message: 'Method Not Allowed' });
        });

        test('should return 404 for completely unknown route (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const event = createMockEvent('GET', '/nonexistent/endpoint', null, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(404);
             expect(JSON.parse(response.body)).toEqual({ message: 'Function route not found' });
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
         });

         test('should return 405 for valid route with unsupported method (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const event = createMockEvent('PATCH', '/accounts', null, { Authorization: null, 'x-api-key': mockApiKey }); // PATCH is not allowed on /accounts
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);
             expect(response.statusCode).toBe(405);
             expect(JSON.parse(response.body)).toEqual({ message: 'Method Not Allowed' });
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
         });
    });


    // == PATCH /accounts/{id} ==
    describe('PATCH /accounts/{id}', () => {
        const updatePayload = { nickname: 'Updated Nickname' };

        test('should update nickname successfully (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            const expectedUpdatedAccount = { ...expectedReturnedAccountBase, nickname: 'Updated Nickname' };

            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').update(...).eq(...).select().single() -> Success
            const updateSingleMock = jest.fn().mockResolvedValueOnce({ data: expectedUpdatedAccount, error: null });
            const updateSelectMock = jest.fn(() => ({ single: updateSingleMock }));
            const updateEqMock = jest.fn(() => ({ select: updateSelectMock }));
            const updateMock = jest.fn(() => ({ eq: updateEqMock }));
            mockFrom.mockImplementationOnce((table) => {
                 if (table === 'accounts') return { update: updateMock };
                 return {};
            });

            const event = createMockEvent('PATCH', `/accounts/${targetAccountId}`, updatePayload);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual(expectedUpdatedAccount);
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(updateMock).toHaveBeenCalledWith({ nickname: 'Updated Nickname' });
            expect(updateEqMock).toHaveBeenCalledWith('id', targetAccountId);
        });

        test('should return 400 if nickname is missing or not a string (JWT Auth)', async () => {
             // Reset mocks specifically for this test
             jest.clearAllMocks(); 
             mockSuccessfulJwtAuth(); // Need to ensure customer lookup is mocked correctly
             
             const event1 = createMockEvent('PATCH', `/accounts/${mockAccountId}`, {}); // Missing nickname
             const event2 = createMockEvent('PATCH', `/accounts/${mockAccountId}`, { nickname: 123 }); // Invalid type
             
             const response1 = await handlerInternal(event1, {}, mockGetCustomerIdForApiKey);
             // Re-mock auth for the second call if needed (cleared by clearAllMocks)
             jest.clearAllMocks(); 
             mockSuccessfulJwtAuth(); 
             const response2 = await handlerInternal(event2, {}, mockGetCustomerIdForApiKey);

             expect(response1.statusCode).toBe(400);
             expect(JSON.parse(response1.body).message).toContain('Missing or invalid field: nickname');
             expect(response2.statusCode).toBe(400);
             expect(JSON.parse(response2.body).message).toContain('Missing or invalid field: nickname');
             // Check that the DB update wasn't called in either case
             expect(mockFrom).not.toHaveBeenCalledWith('accounts'); 
         });

        test('should return 404 if check_account_access fails (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            // Mock 1: RPC check_account_access (fail -> false)
            mockRpc.mockResolvedValueOnce({ data: false, error: null });
            // Mock 2: DB update should not be called

            const event = createMockEvent('PATCH', `/accounts/${mockAccountId}`, updatePayload);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body).message).toBe('Account not found or access denied.');
            expect(mockRpc).toHaveBeenCalledTimes(1);
            expect(mockFrom).not.toHaveBeenCalledWith('accounts');
        });

        test('should return 500 if database update fails with generic error (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             const dbError = { message: 'Update conflict', code: '23505' }; // Example error
             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             // Mock 2: from('accounts').update(...).eq(...).select().single() -> Error
             const updateSingleMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
             const updateSelectMock = jest.fn(() => ({ single: updateSingleMock }));
             const updateEqMock = jest.fn(() => ({ select: updateSelectMock }));
             const updateMock = jest.fn(() => ({ eq: updateEqMock }));
             mockFrom.mockImplementationOnce((table) => {
                  if (table === 'accounts') return { update: updateMock };
                  return {};
             });

             const event = createMockEvent('PATCH', `/accounts/${mockAccountId}`, updatePayload);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(500); // Code returns 500 for non-PGRST116 errors
             expect(JSON.parse(response.body).message).toBe('Database error updating account.');
             expect(mockRpc).toHaveBeenCalledTimes(1);
             expect(updateMock).toHaveBeenCalled();
         });

         test('should return 404 if database update affects 0 rows (PGRST116 error) (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             const dbError = { code: 'PGRST116', message: 'No row found' }; // Specific error for 0 rows updated/selected
             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             // Mock 2: from('accounts').update(...).eq(...).select().single() -> PGRST116 error
             const updateSingleMock = jest.fn().mockResolvedValueOnce({ data: null, error: dbError });
             const updateSelectMock = jest.fn(() => ({ single: updateSingleMock }));
             const updateEqMock = jest.fn(() => ({ select: updateSelectMock }));
             const updateMock = jest.fn(() => ({ eq: updateEqMock }));
             mockFrom.mockImplementationOnce((table) => {
                  if (table === 'accounts') return { update: updateMock };
                  return {};
             });

             const event = createMockEvent('PATCH', `/accounts/${mockAccountId}`, updatePayload);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(404); // Code maps PGRST116 to 404
             expect(JSON.parse(response.body).message).toBe('Account not found for update.');
             expect(mockRpc).toHaveBeenCalledTimes(1);
             expect(updateMock).toHaveBeenCalled();
         });

        // --- API Key Tests ---
        test('should update nickname successfully (API Key Auth)', async () => {
             mockSuccessfulApiKeyAuth();
             const targetAccountId = mockAccountId;
             const payload = { nickname: 'API Update Nickname' }; // Define payload
             const expectedUpdatedAccount = { ...expectedReturnedAccountBase, nickname: payload.nickname };

             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             // Mock 2: from('accounts').update(...).eq(...).select().single() -> Success
             const updateSingleMock = jest.fn().mockResolvedValueOnce({ data: expectedUpdatedAccount, error: null });
             const updateSelectMock = jest.fn(() => ({ single: updateSingleMock }));
             const updateEqMock = jest.fn(() => ({ select: updateSelectMock }));
             const updateMock = jest.fn(() => ({ eq: updateEqMock }));
             mockFrom.mockReturnValueOnce({ update: updateMock }); // No customer table call needed

             const event = createMockEvent('PATCH', `/accounts/${targetAccountId}`, payload, { Authorization: null, 'x-api-key': mockApiKey });
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(200);
             expect(JSON.parse(response.body)).toEqual(expectedUpdatedAccount);
             expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
             expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
             expect(updateMock).toHaveBeenCalledWith(payload); // Check with the correct payload object
             expect(updateEqMock).toHaveBeenCalledWith('id', targetAccountId);
         });
    });

    // == DELETE /accounts/{id} ==
    describe('DELETE /accounts/{id}', () => {
        test('should delete account successfully (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const targetAccountId = mockAccountId;
            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').delete().eq(...) -> Success (count=1)
            const deleteEqMock = jest.fn().mockResolvedValueOnce({ error: null, count: 1 });
            const deleteMock = jest.fn(() => ({ eq: deleteEqMock }));
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { delete: deleteMock };
                return {};
            });

            const event = createMockEvent('DELETE', `/accounts/${targetAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(204); // Expect 204 No Content
            expect(response.body).toBeFalsy(); // No body for 204
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(deleteEqMock).toHaveBeenCalledWith('id', targetAccountId);
        });

        test('should return 404 if check_account_access fails (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             // Mock 1: RPC check_account_access (fail -> false)
             mockRpc.mockResolvedValueOnce({ data: false, error: null });
             // Mock 2: DB delete should not be called

             const event = createMockEvent('DELETE', `/accounts/${mockAccountId}`);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(404);
             expect(JSON.parse(response.body).message).toBe('Account not found or access denied.');
             expect(mockRpc).toHaveBeenCalledTimes(1);
             expect(mockFrom).not.toHaveBeenCalledWith('accounts');
         });

        test('should return 404 if delete affects 0 rows (JWT Auth)', async () => {
             mockSuccessfulJwtAuth();
             // Mock 1: RPC check_account_access (success -> true)
             mockRpc.mockResolvedValueOnce({ data: true, error: null });
             // Mock 2: from('accounts').delete().eq(...) -> Success (count=0)
             const deleteEqMock = jest.fn().mockResolvedValueOnce({ error: null, count: 0 });
             const deleteMock = jest.fn(() => ({ eq: deleteEqMock }));
             mockFrom.mockImplementationOnce((table) => {
                 if (table === 'accounts') return { delete: deleteMock };
                 return {};
             });

             const event = createMockEvent('DELETE', `/accounts/${mockAccountId}`);
             const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

             expect(response.statusCode).toBe(404); // Code maps count=0 to 404
             expect(JSON.parse(response.body).message).toBe('Account not found for deletion.');
             expect(mockRpc).toHaveBeenCalledTimes(1);
             expect(deleteEqMock).toHaveBeenCalledTimes(1);
         });

        test('should return 500 if database delete fails (JWT Auth)', async () => {
            mockSuccessfulJwtAuth();
            const dbError = { message: 'FK constraint violation', code: '23503' }; // Example error
            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').delete().eq(...) -> Error
            const deleteEqMock = jest.fn().mockResolvedValueOnce({ error: dbError, count: null });
            const deleteMock = jest.fn(() => ({ eq: deleteEqMock }));
            mockFrom.mockImplementationOnce((table) => {
                if (table === 'accounts') return { delete: deleteMock };
                return {};
            });

            const event = createMockEvent('DELETE', `/accounts/${mockAccountId}`);
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(500); // Code returns 500
            expect(JSON.parse(response.body).message).toBe('Database error deleting account.');
            expect(mockRpc).toHaveBeenCalledTimes(1);
            expect(deleteEqMock).toHaveBeenCalledTimes(1);
        });

        // --- API Key Tests ---
        test('should delete account successfully (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth();
            const targetAccountId = mockAccountId;
            // Mock 1: RPC check_account_access (success -> true)
            mockRpc.mockResolvedValueOnce({ data: true, error: null });
            // Mock 2: from('accounts').delete().eq(...) -> Success (count=1)
            const deleteEqMock = jest.fn().mockResolvedValueOnce({ error: null, count: 1 });
            const deleteMock = jest.fn(() => ({ eq: deleteEqMock }));
            mockFrom.mockReturnValueOnce({ delete: deleteMock }); // No customer table call needed

            const event = createMockEvent('DELETE', `/accounts/${targetAccountId}`, null, { Authorization: null, 'x-api-key': mockApiKey });
            const response = await handlerInternal(event, {}, mockGetCustomerIdForApiKey);

            expect(response.statusCode).toBe(204);
            expect(response.body).toBeFalsy();
            expect(mockGetCustomerIdForApiKey).toHaveBeenCalledTimes(1);
            expect(mockRpc).toHaveBeenCalledWith('check_account_access', { p_account_id: targetAccountId, p_customer_id: mockCustomerId });
            expect(deleteEqMock).toHaveBeenCalledWith('id', targetAccountId);
        });

    });

}); // End describe suite
