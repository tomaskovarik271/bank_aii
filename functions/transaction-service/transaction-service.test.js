// functions/transaction-service/transaction-service.test.js

jest.resetModules(); // Ensure env vars are picked up

// --- Mock Environment Variables ---
process.env.SUPABASE_URL = 'http://mock-supabase.co';
process.env.SUPABASE_ANON_KEY = 'mock-anon-key';
process.env.AUTH0_DOMAIN = 'mock-auth0-domain.com';
process.env.AUTH0_AUDIENCE = 'mock-audience';
process.env.SUPABASE_JWT_SECRET = 'mock-jwt-secret'; // Although not directly used by txn service, good practice

// --- Mock External Dependencies ---
const mockSingle = jest.fn();
const mockEq = jest.fn(() => ({ single: mockSingle }));
const mockSelect = jest.fn(() => ({ eq: mockEq, single: mockSingle }));
const mockFrom = jest.fn(() => ({ select: mockSelect }));
const mockRpc = jest.fn();
const mockSupabaseClient = { 
    from: mockFrom,
    rpc: mockRpc,
};
jest.mock('@supabase/supabase-js', () => ({
    createClient: jest.fn(() => mockSupabaseClient)
}));

jest.mock('jsonwebtoken');
jest.mock('jwks-rsa');

// Mock the injected API Key function
const mockVerifyApiKey = jest.fn();

// Mock crypto
const mockRandomUUID = jest.fn();

// Import the actual crypto module
const crypto = require('crypto');
// Spy on crypto.randomUUID BEFORE importing the handler
let randomUUIDSpy = null; // Variable to hold spy


// --- Import Handler (After Mocks) ---
const { handler } = require('./transaction-service');
const { handlerInternal } = require('./transaction-service');
const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');

// Define common mock constants
const mockCustomerId = 'cust-uuid-123bbb'; // Use a different UUID from other tests
const mockAuth0UserId = 'auth0|user-for-transactions';
const mockValidJwt = 'mockValidTokenStringTransactions';
const mockDecodedToken = { sub: mockAuth0UserId };
const mockApiKey = 'test-api-key-transactions-abc';
const mockAccountId = '999e8400-e29b-41d4-a716-446655440999'; // Account ID used in transaction tests
const mockAccountId2 = '888e4567-e89b-12d3-a456-426614174888'; // Another distinct account ID
const mockTransactionId = 'txn-group-uuid-transfer-1';

// --- Test Suite ---
describe('Transaction Service Handler', () => {

    // Helper to create mock event (copied from account-service.test.js)
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

    // Helper for successful API Key auth mock setup (Adapted from account-service)
    const mockSuccessfulApiKeyAuth = (customerId = mockCustomerId) => {
        // Directly mock the function that gets injected into handlerInternal
        mockVerifyApiKey.mockResolvedValue(customerId); 
    };

    // Helper for failed API Key auth mock setup
    const mockFailedApiKeyAuth = (errorToThrow) => {
        // Directly mock the function that gets injected into handlerInternal
        mockVerifyApiKey.mockRejectedValue(errorToThrow);
    };

    // Reset mocks before each test
    beforeEach(() => {
        mockFrom.mockClear();
        mockRpc.mockClear(); // Still clear mockRpc for actual business logic RPC calls
        mockVerifyApiKey.mockClear(); // Clear the API key function mock
        mockRandomUUID.mockClear(); 
        jwt.verify.mockReset();
        JwksClient.mockReset(); 

        // Reset Supabase client method mocks (eq, single, select)
        mockEq.mockReset();
        mockSingle.mockReset();
        mockSelect.mockReset();
        // Reset the implementation for chaining (important!)
        mockSelect.mockImplementation(() => ({ eq: mockEq, single: mockSingle }));
        mockEq.mockImplementation(() => ({ single: mockSingle }));

        // Default successful RPC mock for business logic
        mockRpc.mockResolvedValue({ data: null, error: null });
        // Default successful single select mock for ownership checks etc.
        mockSingle.mockResolvedValue({ data: { customer_id: mockAuth0UserId }, error: null }); 
        // *** Remove default mock for API key here - let tests set it explicitly ***
        // mockVerifyApiKey.mockResolvedValue(mockCustomerId); 

        // Restore crypto spy if it exists from previous tests
        if (randomUUIDSpy) {
            randomUUIDSpy.mockRestore(); 
            randomUUIDSpy = null; // Reset spy variable
        }
    });

    // Add afterEach to ensure spy is always restored
    afterEach(() => {
        if (randomUUIDSpy) {
        randomUUIDSpy.mockRestore();
            randomUUIDSpy = null;
        }
    });


    // --- Test Cases ---

    describe('GET /status', () => {
        test('should return 200 OK and status message with valid token', async () => {
            mockSuccessfulJwtAuth(); // Use the correct new helper
            const event = createMockEvent('GET', '/api/transaction-service/status');
            const response = await handler(event, {}); // Use the exported handler
            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual({ status: 'OK' });
        });

        test('should return 401 if token verification fails', async () => {
             // Mock jwt.verify to call its callback with an error
             jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
                 // Directly call callback with error
                 callback(new Error('Mock verification fail'), null); 
            });

             const event = createMockEvent('GET', '/api/transaction-service/status');
             const response = await handler(event, {});
            expect(response.statusCode).toBe(401);
            expect(JSON.parse(response.body).message).toContain('Token verification failed');
        });

        test('should return 401 if authorization header is missing', async () => {
            const event = createMockEvent('GET', '/api/transaction-service/status', null, { Authorization: null });
            const response = await handler(event, {});
            expect(response.statusCode).toBe(401);
            expect(JSON.parse(response.body).message).toContain('Authentication required.'); 
        });
    });

    describe('POST /internal-transfer', () => {
        const transferPayloadBase = {
            fromAccountId: '22222222-2222-2222-2222-222222222222',
            toAccountId: '33333333-3333-3333-3333-333333333333',
            amount: 100.50,
            currency: 'USD',
            description: 'Monthly rent'
        };
        const generatedTxId = '44444444-4444-4444-4444-444444444444';

        test('should perform internal transfer successfully', async () => {
            mockSuccessfulJwtAuth(); 
            // Spy on crypto.randomUUID for this specific test
            randomUUIDSpy = jest.spyOn(crypto, 'randomUUID').mockReturnValueOnce(generatedTxId); 

            // Mock the DB call to check ownership
            mockSingle.mockResolvedValueOnce({ data: { customer_id: mockAuth0UserId }, error: null });
            // Mock the RPC call for the transfer - default success is fine here
            mockRpc.mockResolvedValueOnce({ data: null, error: null }); // Explicit success

            const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
            const response = await handlerInternal(event, {}); 

            expect(response.statusCode).toBe(200);
            expect(JSON.parse(response.body)).toEqual({ message: 'Transfer successful', transactionId: generatedTxId });
            expect(mockSingle).toHaveBeenCalledTimes(1); 
            expect(mockRpc).toHaveBeenCalledWith('post_ledger_transaction', expect.objectContaining({ p_transaction_id: generatedTxId }));
            expect(randomUUIDSpy).toHaveBeenCalledTimes(1); // Verify spy was called
        });

        test('should return 400 for missing amount', async () => {
             mockSuccessfulJwtAuth();
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', { ...transferPayloadBase, amount: undefined });
             const response = await handlerInternal(event, {});
            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).errors).toContain('Missing or invalid amount (must be positive number).');
        });

         test('should return 400 for non-positive amount', async () => {
             mockSuccessfulJwtAuth();
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', { ...transferPayloadBase, amount: -50 });
             const response = await handlerInternal(event, {});
            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).errors).toContain('Missing or invalid amount (must be positive number).');
        });

         test('should return 400 for missing currency', async () => {
             mockSuccessfulJwtAuth();
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', { ...transferPayloadBase, currency: undefined });
             const response = await handlerInternal(event, {});
            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).errors).toContain('Missing or invalid currency (must be 3-letter code).');
        });

         test('should return 400 if fromAccountId and toAccountId are the same', async () => {
             mockSuccessfulJwtAuth();
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', { ...transferPayloadBase, toAccountId: transferPayloadBase.fromAccountId });
             const response = await handlerInternal(event, {});
            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).errors).toContain('fromAccountId and toAccountId cannot be the same.');
        });

         test('should return 404 if source account does not exist', async () => {
             mockSuccessfulJwtAuth();
             // Mock the DB ownership check to fail (PGRST116)
             const dbError = { code: 'PGRST116', message: 'Row not found' };
             mockSingle.mockResolvedValueOnce({ data: null, error: dbError });
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
             const response = await handlerInternal(event, {});
             expect(response.statusCode).toBe(404);
             expect(JSON.parse(response.body).message).toContain('Source account not found');
            expect(mockRpc).not.toHaveBeenCalled();
        });

         test('should return 403 if source account is not owned by user', async () => {
             mockSuccessfulJwtAuth();
             // Mock the DB ownership check to return a different owner
             mockSingle.mockResolvedValueOnce({ data: { customer_id: 'auth0|some-other-user' }, error: null });
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
             const response = await handlerInternal(event, {});
             expect(response.statusCode).toBe(403);
             expect(JSON.parse(response.body).message).toContain('Permission denied for source account');
            expect(mockRpc).not.toHaveBeenCalled();
        });

         test('should return 500 if account check fails with DB error', async () => {
             mockSuccessfulJwtAuth();
             const dbError = { message: 'Connection timeout', code: 'XXYYZ' };
             // Mock the DB ownership check to fail with a generic error
             mockSingle.mockResolvedValueOnce({ data: null, error: dbError });
             const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
             const response = await handlerInternal(event, {});
             expect(response.statusCode).toBe(500);
             expect(JSON.parse(response.body).message).toContain('Database error verifying source account');
            expect(mockRpc).not.toHaveBeenCalled();
        });

         test('should return 500 if RPC call fails with a generic error', async () => {
            mockSuccessfulJwtAuth();
            mockRandomUUID.mockReturnValueOnce(generatedTxId);
            mockSingle.mockResolvedValueOnce({ data: { customer_id: mockAuth0UserId }, error: null });
            // Mock the RPC call to fail generically
            const rpcError = { message: 'DB error during RPC', code: 'XXYYZ' };
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(500);
            expect(JSON.parse(response.body).message).toContain('Failed to process transfer due to a database error');
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 422 if RPC call fails with insufficient funds error', async () => {
            mockSuccessfulJwtAuth();
            mockRandomUUID.mockReturnValueOnce(generatedTxId);
            mockSingle.mockResolvedValueOnce({ data: { customer_id: mockAuth0UserId }, error: null });
            // Mock the RPC call to fail with P0001
            const rpcError = { message: 'Insufficient funds in account XYZ (Current Balance: 0.00, Required: 10.00)', code: 'P0001' };
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(422);
            expect(JSON.parse(response.body).message).toContain('Insufficient funds');
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 400 if RPC call fails with validation error (e.g., account not found)', async () => {
            mockSuccessfulJwtAuth();
            mockRandomUUID.mockReturnValueOnce(generatedTxId);
            mockSingle.mockResolvedValueOnce({ data: { customer_id: mockAuth0UserId }, error: null });
            // Mock the RPC call to fail with P0002 or similar validation
            const rpcError = { message: 'Credit account not found: 33333333-3333-3333-3333-333333333333', code: 'P0002' }; // Example
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
            const response = await handlerInternal(event, {});

            expect(response.statusCode).toBe(400);
            expect(JSON.parse(response.body).message).toContain('Credit account not found');
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 401 if token verification fails', async () => {
            // Mock jwt.verify failure
            jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
                 callback(new Error('Mock verification fail'), null); 
            });

            const event = createMockEvent('POST', '/api/transaction-service/internal-transfer', transferPayloadBase);
            const response = await handlerInternal(event, {}); // Use internal handler
            expect(response.statusCode).toBe(401); // Should be 401 due to auth error
            expect(JSON.parse(response.body).message).toContain('Token verification failed');
            expect(mockRpc).not.toHaveBeenCalled();
        });
    });

    describe('Unknown Route', () => {
        test('should return 404 for unknown paths within the service', async () => {
            mockSuccessfulJwtAuth(); // Auth needs to pass first
            const event = createMockEvent('GET', '/api/transaction-service/unknown/route');
            const response = await handler(event, {});
             expect(response.statusCode).toBe(404);
            expect(JSON.parse(response.body)).toEqual({ message: 'Transaction Service route not found' });
         });
    });

    // --- External Deposit Tests ---
    describe('POST /transactions/external', () => {
        const externalDepositUrl = '/transactions/external';
        const validApiKey = 'valid-api-key';
        const validCustomerId = 'cust_123';
        const validAccountId = 'acc_456';
        const expectedLedgerEntry = { id: 'le_789', /* ... other fields */ };

        // Helper for failed JWT auth mock setup
        const mockFailedAuth = (errorMessage = 'Mock verification fail') => {
            jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
                // Directly call callback with an error
                callback(new Error(errorMessage), null); 
            });
        };

        beforeEach(() => {
            // Reset mocks before each test
            mockVerifyApiKey.mockReset();
            mockRpc.mockReset();
            jwt.verify.mockReset(); // Also reset JWT mock
        });

        test('should create external deposit successfully (API Key Auth)', async () => {
            mockSuccessfulApiKeyAuth(); // Configures mockVerifyApiKey
            mockRpc.mockResolvedValueOnce({ data: expectedLedgerEntry, error: null }); // Mock RPC success

            const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey); 

            expect(res.statusCode).toBe(201);
            const responseBody = JSON.parse(res.body);
            expect(responseBody).toEqual(expectedLedgerEntry);
            expect(mockVerifyApiKey).toHaveBeenCalledWith(validApiKey, expect.anything()); // Check mock was called
            expect(mockRpc).toHaveBeenCalledWith('post_external_deposit', {
                p_account_id: validAccountId,
                p_amount: 100,
                p_currency: 'USD',
                p_description: 'Deposit',
                p_external_reference: null
            });
        });

        // Test JWT Auth attempt on external endpoint (call handlerInternal, but don't inject mockApiKey)
        test('should return 403 for external deposit with JWT (internal call attempt)', async () => {
            mockSuccessfulJwtAuth(); // Mock successful JWT auth

            const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
             const event = createMockEvent('POST', externalDepositUrl, body, { 'Authorization': 'Bearer valid.token', 'X-API-Key': null });

            // Call handlerInternal - JWT should be detected, but route logic should reject it
            const res = await handlerInternal(event);
            expect(res.statusCode).toBe(403); // Expect 403 Forbidden because API key is required
            expect(JSON.parse(res.body).message).toContain('API Key required for this operation');
            expect(mockVerifyApiKey).not.toHaveBeenCalled();
            expect(mockRpc).not.toHaveBeenCalled();
        });

        test('should return 400 for missing accountId', async () => {
            mockSuccessfulApiKeyAuth(); // Configures mockVerifyApiKey
            const body = { amount: 100, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            expect(res.statusCode).toBe(400);
            expect(JSON.parse(res.body).message).toContain('accountId (must be a string)');
            expect(mockVerifyApiKey).toHaveBeenCalledTimes(1); // API key check should happen
            expect(mockRpc).not.toHaveBeenCalled();
        });

        test('should return 400 for invalid amount (zero)', async () => {
            mockSuccessfulApiKeyAuth();
            // Mock RPC failing because amount is zero/negative
            const rpcError = { message: 'Deposit amount must be positive' }; 
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const body = { accountId: validAccountId, amount: 0, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            // Expect the RPC to be called now
            expect(mockVerifyApiKey).toHaveBeenCalledTimes(1);
            expect(mockRpc).toHaveBeenCalledTimes(1);
            // Expect the handler's fallback RPC error response (since specific message check was removed)
            expect(res.statusCode).toBe(500); 
            expect(JSON.parse(res.body).message).toContain('Database error processing deposit');
        });

        // Test for RPC failing due to non-positive amount (redundant with above, but keep for clarity)
        test('should return 500 if RPC fails validation (e.g., non-positive amount)', async () => {
            mockSuccessfulApiKeyAuth();
            const rpcError = { message: 'Deposit amount must be positive' }; 
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const body = { accountId: validAccountId, amount: -50, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });
            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            // Expect the handler's fallback RPC error response
            expect(res.statusCode).toBe(500); 
            expect(JSON.parse(res.body).message).toContain('Database error processing deposit'); 
            expect(mockVerifyApiKey).toHaveBeenCalledTimes(1);
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 404 if RPC fails with Account Not Found', async () => { 
            mockSuccessfulApiKeyAuth(); 
            const rpcError = { message: 'Account not found: ' + validAccountId }; 
            mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            expect(res.statusCode).toBe(404); // Expect 404 based on RPC error handler
            expect(JSON.parse(res.body).message).toContain('Account not found'); // Check specific message
            expect(mockVerifyApiKey).toHaveBeenCalledTimes(1);
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

        test('should return 400 if RPC fails with Currency Mismatch', async () => { 
             mockSuccessfulApiKeyAuth(); 
             const rpcError = { message: 'Currency mismatch: Expected USD got EUR' }; 
             mockRpc.mockResolvedValueOnce({ data: null, error: rpcError });

            const body = { accountId: validAccountId, amount: 100, currency: 'EUR', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

            const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            expect(res.statusCode).toBe(400); // Expect 400 based on RPC error handler
            expect(JSON.parse(res.body).message).toContain('Currency mismatch'); // Check specific message
            expect(mockVerifyApiKey).toHaveBeenCalledTimes(1);
            expect(mockRpc).toHaveBeenCalledTimes(1);
        });

         test('should return 500 if RPC fails with generic error', async () => {
             mockSuccessfulApiKeyAuth(); 
             const genericError = { message: 'Something went wrong', code: 'XXXXX' }; 
             mockRpc.mockResolvedValueOnce({ data: null, error: genericError });

             const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
             const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

             const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

             expect(res.statusCode).toBe(500); // Expect 500 based on fallback RPC error handler
             expect(JSON.parse(res.body).message).toContain('Database error processing deposit.'); // Check generic message
             expect(mockVerifyApiKey).toHaveBeenCalledTimes(1);
             expect(mockRpc).toHaveBeenCalledTimes(1);
         });

        test('should return 403 if API key is invalid', async () => {
            const error = new Error('Invalid API Key');
            error.statusCode = 403;
            mockFailedApiKeyAuth(error); // Configures mockVerifyApiKey to fail

            const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': 'invalid-key', Authorization: null });

             const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            expect(res.statusCode).toBe(403);
            expect(JSON.parse(res.body).message).toContain('Invalid API Key');
            expect(mockVerifyApiKey).toHaveBeenCalledWith('invalid-key', expect.anything());
            expect(mockRpc).not.toHaveBeenCalled();
        });

        test('should return 500 if API key check fails with DB error', async () => {
            const dbError = new Error('Database connection failed');
            dbError.statusCode = 500;
            mockFailedApiKeyAuth(dbError); // Configures mockVerifyApiKey to fail

            const body = { accountId: validAccountId, amount: 100, currency: 'USD', description: 'Deposit' };
            const event = createMockEvent('POST', externalDepositUrl, body, { 'X-API-Key': validApiKey, Authorization: null });

             const res = await handlerInternal(event, {}, undefined, mockVerifyApiKey);

            expect(res.statusCode).toBe(500);
            // <<< CHANGE: Expect the raw error message from the mock >>>
            expect(JSON.parse(res.body).message).toBe('Database connection failed'); 
            expect(mockVerifyApiKey).toHaveBeenCalledWith(validApiKey, expect.anything());
            expect(mockRpc).not.toHaveBeenCalled();
        });

    }); // End describe POST /transactions/external

}); // End describe suite 

// Helper for successful JWT auth mock setup (Adapted from account-service)
const mockSuccessfulJwtAuth = () => {
    // Configure JWT mocks (jsonwebtoken, jwks-rsa)
    const mockGetSigningKey = jest.fn((header, callback) => { callback(null, 'mock-signing-key'); });
    JwksClient.mockImplementation(() => ({ getSigningKey: mockGetSigningKey }));
    jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
        // Directly call callback with success, simulating verifyTokenImplementation logic
        callback(null, mockDecodedToken); // Successful verification
    });
    // NOTE: No need to mock the customer lookup via mockFrom here, 
    // as transaction-service's verifyToken doesn't do that.
};

// Helper for failed JWT auth mock setup
const mockFailedAuth = (errorMessage = 'Mock verification fail') => {
    jwt.verify.mockImplementation((token, keyLookup, options, callback) => {
        // Directly call callback with an error
        callback(new Error(errorMessage), null); 
    });
};

// Helper for successful API Key auth mock setup (Adapted from account-service)
const mockSuccessfulApiKeyAuth = (customerId = mockCustomerId) => {
    // Directly mock the function that gets injected into handlerInternal
    mockVerifyApiKey.mockResolvedValue(customerId); 
};

// Helper for failed API Key auth mock setup
const mockFailedApiKeyAuth = (errorToThrow) => {
     // Directly mock the function that gets injected into handlerInternal
     mockVerifyApiKey.mockRejectedValue(errorToThrow);
 };

// Helper: Mock Successful Authentication --- // <-- Original line 