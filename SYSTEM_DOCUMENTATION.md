# Core Banking System - Current Documentation

_Last Updated: 2024-07-29_

This document provides a snapshot of the Core Banking System project based on the implementation completed so far, following the `PROJECT_KICKOFF_GUIDE.md`.

## 1. Overview

*   **Goal:** Build a core banking system using microservices deployed on Netlify, compliant with relevant regulations.
*   **Architecture:** Serverless microservices hosted on Netlify, leveraging Netlify Functions for backend logic, Supabase (PostgreSQL) for the database, and Auth0 for identity management.

## 2. Core Technologies

*   **Hosting & Serverless Functions:** [Netlify](https://www.netlify.com/)
    *   Provides integrated hosting, serverless functions (Node.js), CI/CD, CDN, environment management.
    *   `netlify.toml` defines build, deploy, and dev settings.
    *   `netlify dev` CLI command used for local development simulation.
*   **Database:** [Supabase](https://supabase.com/) (Managed PostgreSQL)
    *   Provides managed PostgreSQL database, backend features (though primarily used for DB).
    *   Schema managed via Supabase Migrations (`supabase/migrations/`).
    *   Row Level Security (RLS) is used for data access control.
    *   RPC functions (`plpgsql`) used for atomic database operations (e.g., ledger posting).
*   **Identity & Access Management (IAM):** [Auth0](https://auth0.com/)
    *   External SaaS provider for authentication and authorization.
    *   Issues JWTs (RS256 signed) used to secure Netlify Functions.
    *   M2M (Machine-to-Machine) application used for backend testing/scripts.
*   **Runtime:** [Node.js](https://nodejs.org/) (LTS version recommended)
    *   Language used for Netlify Functions.
*   **Package Management:** [npm](https://www.npmjs.com/)
    *   Used for managing Node.js dependencies (`package.json`, `package-lock.json`).

## 3. Project Setup & Structure

*   **Initialization:** Standard `npm init -y`, `git init`.
*   **Core Dependencies:**
    *   Runtime: `@supabase/supabase-js`, `jsonwebtoken`, `jwks-rsa`.
    *   Development: `netlify-cli`, `jest`, `eslint`, `dotenv` (for local integration testing).
*   **Directory Structure:**
    ```
    /
    ├── functions/         # Netlify functions root directory
    │   ├── customer-service/
    │   │   ├── customer-service.js
    │   │   └── customer-service.test.js # Jest tests
    │   ├── account-service/
    │   │   ├── account-service.js
    │   │   └── account-service.test.js # Jest tests
    │   └── transaction-service/
    │       ├── transaction-service.js
    │       └── transaction-service.test.js # Jest tests
    ├── public/            # Static assets (served by netlify dev)
    │   └── index.html     # Simple placeholder
    ├── supabase/          # Supabase local dev/migration files
    │   ├── migrations/
    │   │   ├── xxxxxxxxxxxxxx_init_schema.sql
    │   │   ├── xxxxxxxxxxxxxx_create_ledger_rpcs.sql
    │   │   └── xxxxxxxxxxxxxx_add_customer_rls.sql
    │   ├── config.toml    # Local Supabase config
    │   └── ...            # Other Supabase files (e.g., .gitignore)
    ├── .env               # Local environment variables (used as workaround)
    ├── .eslintrc.json     # ESLint configuration
    ├── .git/
    ├── .gitignore
    ├── .netlify/          # Netlify state directory (added by `netlify link`)
    ├── netlify.toml       # Netlify configuration file
    ├── node_modules/
    ├── package.json
    ├── package-lock.json
    ├── PROGRESS_TRACKER.md # Progress tracking document
    ├── SYSTEM_DOCUMENTATION.md # This documentation
    ├── PROJECT_KICKOFF_GUIDE.md # Original guide
    ├── tests/                 # Integration tests
    │   └── integration/
    │       └── core-flow.test.js
    └── ...
    ```
*   **Configuration Files:**
    *   `.gitignore`: Excludes `node_modules/`, `.env*`, logs.
    *   `netlify.toml`: Defines build (`publish = "public/"`), functions (`functions = "functions/"`), dev server settings, redirects (`/api/*` proxies to `/.netlify/functions/:splat`), and the build command (`npm run lint && npm test`).
    *   `package.json`: Lists dependencies and project info. Includes scripts:
        *   `lint`: `eslint -c .eslintrc.json functions/**/*.js`
        *   `test`: `jest --testPathIgnorePatterns=tests/integration` (Runs unit tests only, used in CI)
        *   `test:integration`: `jest tests/integration` (Runs integration tests, requires local .env)
        *   `test:all`: `jest` (Runs all tests)
    *   `.eslintrc.json`: Configures ESLint rules for code quality. Includes Jest environment (`"env": { "jest": true }`).

## 4. Cloud Configuration

*   **Auth0:**
    *   API (Resource Server) created (Audience: `https://api.core-banking-ai`).
    *   M2M Application created for testing (Client ID/Secret obtained).
*   **Supabase:**
    *   Project created (`core-banking-ai-dev`, ID: `fgnjpkpynsyaevihpukc`).
    *   Project URL and `service_role` key obtained.
*   **Netlify:**
    *   Site created from Git repository (`subtle-pegasus-65cf9c`).
    *   Environment Variables configured in UI: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`. Scope must include "Local development" or be "All scopes".

## 5. Development Workflow (`netlify dev`)

*   **Linking:** Local project linked to Netlify site via `npx netlify link`.
*   **Execution:** `npx netlify dev` starts a local server:
    *   Serves static files from `public/`.
    *   Runs Netlify Functions from `functions/` locally.
    *   Applies redirects from `netlify.toml` (e.g., `/api/*`).
    *   **Injects Environment Variables:** Intended to inject variables from linked Netlify site UI.
        *   **Workaround:** A local `.env` file is currently used because variables from the Netlify UI were not being correctly injected during testing.
*   **Local Testing:** Functions tested using `curl` commands, passing Auth0 M2M token in `Authorization: Bearer` header.

## 6. Implemented Services

### 6.1. `transaction-service`

*   **File:** `functions/transaction-service/transaction-service.js`
*   **Purpose:** Handles money movement between accounts (internal transfers) and external deposits.
*   **Tests:** Comprehensive unit tests available in `transaction-service.test.js`.
*   **Authentication:**
    *   **JWT:** Uses `Authorization: Bearer <token>` for user-initiated actions (e.g., `/internal-transfer`). Validated using `jsonwebtoken` and `jwks-rsa` against Auth0.
    *   **API Key:** Uses `X-API-Key: <key>` header for system-to-system actions (e.g., `/transactions/external`). Validated by calling the `get_customer_id_for_api_key` Supabase RPC function.
*   **Endpoints Implemented:**
    *   `GET /api/transaction-service/status`
        *   **Method:** `GET`
        *   **Auth:** JWT required.
        *   **Purpose:** Simple health check.
        *   **Response:** `200 OK` with `{ "status": "OK" }`.
    *   `POST /api/transaction-service/internal-transfer`
        *   **Method:** `POST`
        *   **Auth:** JWT required.
        *   **Purpose:** Executes a transfer between two accounts owned by the authenticated user.
        *   **Request Body:**
            ```json
            {
              "fromAccountId": "uuid",
              "toAccountId": "uuid",
              "amount": 100.50,
              "currency": "USD",
              "description": "Optional transfer description"
            }
            ```
        *   **Response:**
            *   `200 OK`: `{ "message": "Transfer successful", "transactionId": "uuid" }`
            *   `400 Bad Request`: Invalid input (missing fields, non-positive amount, same accounts, etc.).
            *   `403 Forbidden`: User does not own the `fromAccountId`.
            *   `404 Not Found`: `fromAccountId` does not exist or is not accessible.
            *   `422 Unprocessable Entity`: Insufficient funds (custom RPC error `P0001`).
            *   `500 Internal Server Error`: Database error during account check or RPC call.
    *   `POST /api/transaction-service/transactions/external`
        *   **Method:** `POST`
        *   **Auth:** API Key required (`X-API-Key` header).
        *   **Purpose:** Allows external systems (e.g., payment gateway) to deposit funds into an account. Relies on the `post_external_deposit` RPC for core logic and validation.
        *   **Request Body:**
            ```json
            {
              "accountId": "uuid",
              "amount": 100.50,
              "currency": "USD",
              "description": "Deposit description",
              "externalReference": "optional_reference_string" // e.g., Payment Gateway Charge ID
            }
            ```
        *   **Response:**
            *   `201 Created`: Returns the created ledger entry object from the `post_external_deposit` RPC.
                ```json
                // Example Shape (actual fields depend on RPC return)
                {
                  "id": "le_uuid",
                  "transaction_id": "txn_uuid",
                  "account_id": "acc_uuid",
                  "type": "DEPOSIT",
                  "amount": 100.50,
                  "currency": "USD",
                  "description": "Deposit description",
                  "external_reference": "optional_reference_string",
                  "created_at": "timestamp"
                }
                ```
            *   `400 Bad Request`: Invalid input (missing fields, invalid types). Also returned for RPC validation errors like `Currency mismatch` or `Account is inactive`.
            *   `401 Unauthorized`: Missing API Key.
            *   `403 Forbidden`: Invalid API Key (if key exists but is not valid, determined by `get_customer_id_for_api_key` RPC).
            *   `404 Not Found`: `accountId` does not exist (from RPC error).
            *   `500 Internal Server Error`: Database error during API key verification or RPC call.
*   **Key Features:**
    *   Handles both Auth0 JWT (for internal transfers) and API Key validation (for external deposits).
    *   Input validation (basic structure/type checks in handler, business logic checks in RPCs).
    *   Uses Supabase RPCs (`post_ledger_transaction`, `post_external_deposit`, `get_customer_id_for_api_key`) for atomic database operations and validation.
    *   Specific error handling for various failure scenarios (validation, auth, insufficient funds, RPC errors).

### 6.2. `customer-service`

*   **File:** `functions/customer-service/customer-service.js`
*   **Purpose:** Manages customer profiles.
*   **Tests:** Comprehensive unit tests available in `customer-service.test.js`.
*   **Endpoints Implemented:**
    *   `GET /api/customer-service/me`: Retrieves the customer profile linked to the authenticated user.
    *   `POST /api/customer-service/`: Creates a new customer profile, linking it to the authenticated user.
    *   `PATCH /api/customer-service/me`: Updates the profile details (name, DOB, address) for the authenticated user.
    *   `DELETE /api/customer-service/me`: Deletes the customer profile for the authenticated user.
*   **Key Features:**
    *   Auth0 JWT validation for all requests.
    *   Fetches/Creates/Updates/Deletes records in the `customers` table using Supabase client.
    *   Uses `auth0_user_id` from the JWT `sub` claim to link/query records.
    *   Handles specific database errors (e.g., "Not Found" on GET/PATCH/DELETE, unique constraint violation on POST).

### 6.3. `account-service`

*   **File:** `functions/account-service/account-service.js`
*   **Purpose:** Manages bank accounts (creation, retrieval, listing, update, delete) and retrieves account transaction history.
*   **Tests:** Comprehensive unit tests available in `account-service.test.js`.
*   **Authentication:** Handles both JWT (`Authorization: Bearer`) and API Key (`X-API-Key`) authentication. API Key validation uses the `get_customer_id_for_api_key` RPC.
*   **Endpoints Implemented:**
    *   `POST /api/account-service/accounts`: Creates a new account (CHECKING/SAVINGS) linked to the authenticated user's customer profile. (JWT Auth required).
    *   `GET /api/account-service/accounts`: Lists accounts for the authenticated customer. (JWT or API Key Auth).
    *   `GET /api/account-service/accounts/{accountId}`: Retrieves details for a specific account, including calculated balance. (JWT or API Key Auth).
    *   `PATCH /api/account-service/accounts/{accountId}`: Updates the nickname for a specific account. (JWT Auth required).
    *   `DELETE /api/account-service/accounts/{accountId}`: Deletes a specific account. (JWT Auth required).
    *   `GET /api/account-service/accounts/{accountId}/transactions`: Retrieves the list of ledger entries for a specific account.
        *   **Method:** `GET`
        *   **Auth:** JWT or API Key required (uses `check_account_access` RPC for authorization).
        *   **Purpose:** Fetches the transaction history (ledger entries) for an account the authenticated user has access to.
        *   **Response:**
            *   `200 OK`: Returns an array of ledger entry objects.
                ```json
                // Example Shape (matches ledger_entries table + RPC return)
                [
                  {
                    "id": 1,
                    "created_at": "2024-01-15T10:00:00Z",
                    "transaction_id": "tx-uuid-1",
                    "account_id": "acc_uuid",
                    "entry_type": "DEBIT",
                    "amount": 50.00,
                    "currency": "USD",
                    "description": "Payment"
                  },
                  { ... next entry ...}
                ]
                ```
            *   `400 Bad Request`: Invalid `accountId` format in the path.
            *   `401 Unauthorized`: Missing or invalid authentication (JWT or API Key).
            *   `403 Forbidden`: Authenticated user does not have access to the requested `accountId` (checked via `check_account_access` RPC).
            *   `404 Not Found`: Account not found (returned by access check or if `get_account_transactions` RPC fails with 'Not Found').
            *   `500 Internal Server Error`: Database error during access check or transaction fetch RPC call.
    *   `POST /api/account-service/accounts/{accountId}/transactions`: (Not Implemented - returns 501)
*   **Key Features:**
    *   Handles both JWT and API Key authentication.
    *   Uses `check_account_access` Supabase RPC for authorization on specific account operations (GET/PATCH/DELETE specific account, GET transactions).
    *   Calls `calculate_balance` Supabase RPC for `GET /accounts/{accountId}`.
    *   Calls `get_account_transactions` Supabase RPC for `GET /accounts/{accountId}/transactions`.
    *   Generates placeholder unique `account_number` using UUID.

## 7. Database Schema & Migrations (Supabase)

*   **Tooling:** Supabase CLI (`brew install supabase`) used for managing schema.
*   **Workflow:**
    1.  `supabase login`
    2.  `supabase link --project-ref <project_id>`
    3.  `supabase migration new <migration_name>` (Creates SQL file)
    4.  Add SQL DDL/DML to migration file.
    5.  `supabase start` (Ensures local Docker stack is running)
    6.  `supabase db reset` (Applies all migrations locally to clean Docker DB)
    7.  `supabase db push` (Applies new migrations to linked remote DB)
*   **Implemented Migrations:** (Refer to `supabase/migrations/` for full details)
    *   Initial schema setup (`customers`, `accounts`, `ledger_entries`, etc.).
    *   Core RPC functions (`post_ledger_transaction`, `calculate_balance`, `post_external_deposit`, `check_account_access`, `get_customer_id_for_api_key`, `get_account_transactions`).
    *   RLS policies for data security.
*   **Key RPC Functions:**
    *   `post_ledger_transaction`: Atomically creates debit/credit entries for internal transfers. Includes balance checks and permission enforcement.
    *   `post_external_deposit`: Creates a single credit entry for external deposits. Includes validation checks.
    *   `calculate_balance`: Calculates the current balance for an account based on ledger entries.
    *   `check_account_access`: Verifies if a given `customer_id` owns a specific `account_id`. Used for authorization.
    *   `get_customer_id_for_api_key`: Validates an API key and returns the associated `customer_id`. Used for API Key authentication.
    *   `get_account_transactions`: Retrieves ledger entries for a specific account.

## 8. Testing & Deployment

*   **Linting:** ESLint (`npm run lint`) is used to enforce code style and catch potential errors. It's configured in `.eslintrc.json` (including the Jest environment) and run as part of the Netlify build process.
*   **Unit Testing:** Jest (`npm test`) is used for unit testing individual functions and service handlers. Mocks are used extensively for external dependencies (Supabase client, JWT libraries).
    *   Tests are located alongside the service files (e.g., `functions/customer-service/customer-service.test.js`).
    *   The `test` script in `package.json` (`jest --testPathIgnorePatterns=tests/integration`) excludes integration tests and is run during the Netlify build.
*   **Integration Testing:** Jest (`npm run test:integration`) is used for end-to-end tests that interact with deployed or locally running services.
    *   Tests are located in the `tests/integration` directory.
    *   These tests typically require environment variables for external services (e.g., Auth0 M2M credentials for making real API calls). These should be managed locally (e.g., via a `.env` file) and **not** run during the standard Netlify build.
    *   The `test:integration` script in `package.json` specifically targets this directory (`jest tests/integration`).
*   **Deployment:**
    *   Deployment is handled automatically by Netlify upon pushes to the main GitHub branch.
    *   The build command (`npm run lint && npm test`) defined in `netlify.toml` ensures code is linted and unit tests pass before deployment.
    *   Build issues related to ESLint configuration (`env.jest`) and integration tests running in CI have been resolved. Environment variables for Supabase/Auth0 are configured in the Netlify site UI.

## 9. Security Considerations

*   **Authentication:** Handled by Auth0. Users/applications obtain JWTs from Auth0.
*   **Function Authorization:**
    *   Netlify functions (`transaction-service`, `customer-service`, `account-service`) validate the JWT using the Auth0 JWKS endpoint (`jwks-rsa`) and `jsonwebtoken` library.
    *   Checks include signature, audience (`AUTH0_AUDIENCE`), and issuer (`AUTH0_DOMAIN`).
    *   The validated token's `sub` claim (Auth0 User ID) is used for linking data (`customers.auth0_user_id`).
*   **Database Authorization (RLS):**
    *   Supabase RLS policies provide database-level access control.
    *   Policies use the user's identity from the JWT (`(current_setting('request.jwt.claims', true)::jsonb ->> 'sub')` for non-UUID subs, or potentially `auth.uid()` if subs are UUIDs) to filter data (e.g., allow access only if `customers.auth0_user_id` matches the JWT identity).
    *   `accounts` table policies use a helper function (`get_my_customer_id`) to check ownership based on the account's `customer_id` matching the authenticated user's customer ID.
    *   **Client Initialization:** Netlify functions correctly initialize the Supabase client using the validated user JWT passed in the `Authorization` header. This ensures that database operations performed via this client instance respect the user's RLS policies.
    *   **API Key Flow:** In `account-service`, the API key authentication path uses the `anon` key but relies on the `customerId` verified via the `get_customer_id_for_api_key` RPC function. RLS policies and function logic must correctly authorize based on this `customerId`.

## 10. API Routing

*   **Netlify Proxy:** `netlify.toml` defines a redirect: `[[redirects]] from = "/api/*" to = "/.netlify/functions/:splat" status = 200`. This routes incoming requests starting with `/api/` to the corresponding Netlify Function.
*   **Internal Function Routing:** Each function (e.g., `customer-service.js`) inspects `event.httpMethod` and calculates a `subPath` (the path *after* the function name prefix) to handle different actions (e.g., `GET /me`, `POST /`). 
    *   `customer-service` handles `/me`, `/`.
    *   `account-service` handles `/accounts`, `/accounts/{accountId}`.
    *   `transaction-service` handles `/status`, `/internal-transfer`. 

## 11. Architectural Notes

*   **Synchronous Communication:** Currently, the services primarily interact directly with the Supabase database (including RPCs) or operate independently. Inter-service communication is synchronous.
*   **Integration Testing:** An integration test suite (`tests/integration/core-flow.test.js`) verifies the core customer verification and account creation flow against a running instance, complementing unit and manual tests. Transfer-related tests are currently skipped pending implementation of a deposit mechanism.
*   **Future Asynchronous Architecture:** The long-term plan involves refactoring towards an event-driven, asynchronous communication model, potentially using a service like Inngest, to improve decoupling and resilience. This is noted in the `PROJECT_KICKOFF_GUIDE.md`. 

## 12. Known Issues & Future Refactoring

*   **API Key RLS Interaction (`account-service`):**
    *   **Note:** While the JWT path correctly uses user-scoped clients, the API Key path in `account-service` uses the `anon` key. 
    *   **Impact:** RLS policies and helper functions (like `check_account_access`) *must* correctly handle authorization based on the `customerId` passed as an argument or variable, as `auth.uid()` or `current_setting(...)` will not contain the end-user's identity in this flow. This requires careful policy design.
    *   **Recommendation:** Ensure all RLS policies and helper functions used by API-key-accessible paths correctly implement authorization checks based on the provided `customerId` parameter.
*   **Database Function Volatility (`calculate_balance`):**
    *   **Issue:** The `public.calculate_balance` function was initially marked `STABLE`. This caused incorrect behavior within the `public.post_ledger_transaction` function, where the insufficient funds check relied on an up-to-date balance reading within the same transaction. The `STABLE` designation potentially led to stale reads or incorrect query planning.
    *   **Resolution:** The function has been changed to `VOLATILE` to ensure it is re-evaluated correctly each time it's called, providing the necessary consistency for the transaction check. 

## 13. Pre-Launch Considerations for Live Banking Operations

Moving from the current prototype to a live, regulated banking operation requires addressing several critical areas **before** adding significant new features. These foundational elements are essential for security, compliance, and operational stability: 

1.  **Compliance & Legal Foundation:**
    *   Obtain necessary banking licenses.
    *   Conduct a deep dive into all applicable regulations (AML/CFT, GDPR, PSD2, etc.) with legal/compliance experts.
    *   Implement a robust AML/KYC solution and onboarding process.
    *   Finalize and vet Terms of Service and Privacy Policies.
    *   Design and implement regulatory reporting mechanisms.

2.  **Security Hardening & Verification:**
    *   Perform comprehensive third-party penetration testing and remediate findings.
    *   Establish a continuous vulnerability management program (scanning, remediation).
    *   Implement/configure WAF and DDoS protection.
    *   Harden IAM configurations (Auth0 policies, Supabase roles, internal staff access). Minimize `service_role` key usage.
    *   Implement comprehensive, immutable audit logging for all sensitive operations.

3.  **Operational Robustness & Resilience:**
    *   Set up comprehensive monitoring (APM, infrastructure, business transactions) and actionable alerting.
    *   Develop and test a formal incident response plan.
    *   Verify, test, and document disaster recovery and backup procedures (including RTO/RPO).
    *   Define and monitor Service Level Objectives (SLOs).

4.  **Data Integrity & Financial Controls:**
    *   Implement automated ledger verification and reconciliation processes.
    *   Design and implement fraud detection mechanisms.
    *   Refine error handling for financial transactions to ensure clarity and consistency.

5.  **Scalability & Performance Validation:**
    *   Conduct realistic load testing to identify and address bottlenecks.
    *   Perform performance tuning based on testing results.

6.  **Architectural Refinements:**
    *   Evaluate and potentially implement the planned asynchronous architecture (e.g., using Inngest) for critical flows like transfers to enhance resilience *before* launch. 

## 14. Deployment

*   **Platform:** Netlify
*   **Method:** Continuous Deployment linked to the `main` branch of the GitHub repository.
*   **Process:** Pushing commits to `main` automatically triggers a build and deployment on Netlify.
*   **Status:** The latest changes (including transaction retrieval) were deployed on May 2, 2024.

## 15. Testing

*   **Automated Testing Strategy:**
    *   **Running Tests:** Execute `npm test` from the project root.
    *   **Specific Service:** Execute `npm test functions/<service-name>/<service-name>.test.js` (e.g., `npm test functions/transaction-service/transaction-service.test.js`).
    *   **Test Types:**
        *   **Unit Tests:** Located alongside the service code (e.g., `functions/account-service/account-service.test.js`). These tests focus on isolating and verifying the logic within a single service function.
        *   **Integration Tests:** Located in `tests/integration/`. Currently, `core-flow.test.js` verifies the end-to-end interaction between services for critical user flows like registration and account creation. These tests run against a live (though potentially locally simulated via `netlify dev`) environment.
    *   **Mocking Strategy:**
        *   **External Dependencies:** External libraries and modules (e.g., `@supabase/supabase-js`, `jsonwebtoken`, `jwks-rsa`, `crypto`) are mocked using `jest.mock()` at the top of the test files.
        *   **Environment Variables:** Environment variables (`SUPABASE_URL`, `AUTH0_DOMAIN`, etc.) required by the services are mocked by setting `process.env.VAR_NAME = 'mock-value'` *before* the service module is required in the test file.
        *   **Supabase Client:**
            *   The `createClient` function from `@supabase/supabase-js` is mocked to return a consistent mock client object.
            *   This mock client exposes Jest mock functions (`mockFrom`, `mockRpc`) for its core methods.
            *   Individual tests are responsible for configuring the behavior of `mockFrom` and `mockRpc` based on the specific database interactions expected for that test case. This often involves setting up mock function chains (e.g., `mockFrom.mockImplementationOnce(...)` returning objects with further mock functions like `select`, `eq`, `single`, `insert`, `update`, `delete`).
        *   **Authentication:**
            *   JWT verification (`jsonwebtoken.verify`, `jwks-rsa.getSigningKey`) is mocked to simulate successful or failed authentication scenarios.
            *   Helper functions like `mockSuccessfulJwtAuth` and `mockFailedAuth` in test files encapsulate common authentication mock setups.
            *   For services accepting API keys, the injected dependency function (e.g., `_getCustomerIdForApiKey` in `transaction-service`) is mocked directly using `jest.fn()` and configured via helpers like `mockSuccessfulApiKeyAuth` or `mockFailedApiKeyAuth`.
    *   **Key Principles:**
        *   Tests should be independent and reset mocks (`jest.clearAllMocks()`, `mockFn.mockReset()`, etc.) in `beforeEach` blocks.
        *   Tests configure the specific mock behaviors they need, rather than relying on global mock setups.
        *   Focus on testing the service logic, mocking away the actual external interactions.

# ... (Authentication, Environment Variables, Local Development, Deployment unchanged) ... 

## 16. Pre-Launch Considerations for Live Banking Operations

Moving from the current prototype to a live, regulated banking operation requires addressing several critical areas **before** adding significant new features. These foundational elements are essential for security, compliance, and operational stability:

1.  **Compliance & Legal Foundation:**
    *   Obtain necessary banking licenses.
    *   Conduct a deep dive into all applicable regulations (AML/CFT, GDPR, PSD2, etc.) with legal/compliance experts.
    *   Implement a robust AML/KYC solution and onboarding process.
    *   Finalize and vet Terms of Service and Privacy Policies.
    *   Design and implement regulatory reporting mechanisms.

2.  **Security Hardening & Verification:**
    *   Perform comprehensive third-party penetration testing and remediate findings.
    *   Establish a continuous vulnerability management program (scanning, remediation).
    *   Implement/configure WAF and DDoS protection.
    *   Harden IAM configurations (Auth0 policies, Supabase roles, internal staff access). Minimize `service_role` key usage.
    *   Implement comprehensive, immutable audit logging for all sensitive operations.

3.  **Operational Robustness & Resilience:**
    *   Set up comprehensive monitoring (APM, infrastructure, business transactions) and actionable alerting.
    *   Develop and test a formal incident response plan.
    *   Verify, test, and document disaster recovery and backup procedures (including RTO/RPO).
    *   Define and monitor Service Level Objectives (SLOs).

4.  **Data Integrity & Financial Controls:**
    *   Implement automated ledger verification and reconciliation processes.
    *   Design and implement fraud detection mechanisms.
    *   Refine error handling for financial transactions to ensure clarity and consistency.

5.  **Scalability & Performance Validation:**
    *   Conduct realistic load testing to identify and address bottlenecks.
    *   Perform performance tuning based on testing results.

6.  **Architectural Refinements:**
    *   Evaluate and potentially implement the planned asynchronous architecture (e.g., using Inngest) for critical flows like transfers to enhance resilience *before* launch. 