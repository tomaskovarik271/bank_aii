# Core Banking System - Regulatory Overview Document

**Version:** 1.0 (Draft)
**Date:** YYYY-MM-DD

## 1. Executive Summary

*   **Purpose:** To provide a technical and architectural overview of the Core Banking System prototype for regulatory assessment, focusing on security, compliance aspects, data integrity, and operational design.
*   **System Goal:** Implement foundational core banking functionalities (customer management, account management, internal transfers, ledger) using a modern, secure, and scalable serverless microservices architecture.
*   **Key Technologies:** Netlify (Serverless Functions, Hosting, CI/CD), Supabase (Managed PostgreSQL Database with RLS), Auth0 (Identity Provider for customer authentication).
*   **Current Status:** Prototype phase with core functionalities implemented. Key focus areas include secure authentication/authorization patterns, atomic ledger operations via database functions, and automated testing. The system demonstrates adherence to principles like least privilege and secure-by-default.

## 2. System Architecture

*   **Style:** Serverless Microservices architecture hosted on Netlify.
*   **Components:**
    *   **`customer-service` (Netlify Function):** Manages customer identity (linked to Auth0) and profile data (CRUD operations).
    *   **`account-service` (Netlify Function):** Manages deposit accounts (CRUD operations), including status and details. Interfaces with ledger for balance calculation. Supports API Key authentication for specific M2M use cases.
    *   **`transaction-service` (Netlify Function):** Orchestrates internal fund transfers, validates requests, and invokes ledger operations.
    *   **`ledger-service` (Logical Service):** Core financial logic implemented as atomic PostgreSQL functions (RPCs) within the Supabase database, ensuring double-entry bookkeeping integrity.
*   **Database:** Supabase Managed PostgreSQL instance.
*   **Authentication Provider:** Auth0 (handles user login, credential management, token issuance).
*   **Communication Patterns:** Primarily synchronous RESTful API calls between client/frontend (not yet built) and Netlify Functions, and between Functions and Supabase (via Supabase client library and RPC calls).
    *   *Note:* Asynchronous communication patterns (e.g., using Inngest for eventing/workflows) are part of the future architectural plan for enhanced resilience but are not yet implemented in the current prototype.
*   **Diagram:**
    ```
    [Placeholder for High-Level Architecture Diagram]
    (Diagram should show Frontend -> Netlify Functions (customer, account, transaction) -> Supabase DB (Tables + RPCs) <-> Auth0)
    ```

## 3. Technology Stack & Rationale

*   **Hosting & Serverless Functions: Netlify**
    *   **Technology:** Netlify Functions (Node.js runtime), Netlify CDN, Netlify CI/CD.
    *   **Rationale:** Simplifies deployment and infrastructure management via Git-driven workflows, provides scalability, integrated environment variable handling, and developer tooling (`netlify dev`). Reduces operational burden compared to managing traditional servers.
*   **Database: Supabase (PostgreSQL)**
    *   **Technology:** Managed PostgreSQL database service.
    *   **Rationale:** Provides reliable, transactional SQL database (essential for financial data), Row Level Security (RLS) for fine-grained data access control, connection pooling, and capability to embed critical logic via Database Functions (RPCs) for atomicity. Reduces DB operational overhead.
*   **Identity & Access Management (IAM): Auth0**
    *   **Technology:** External Identity-as-a-Service (IDaaS) provider.
    *   **Rationale:** Mature, dedicated IAM platform with strong security features (MFA support, breach detection), compliance certifications (SOC 2, ISO 27001), and support for standards like OpenID Connect/OAuth 2.0. Offloads the complexity of building and maintaining a secure identity system.
*   **Backend Runtime: Node.js**
    *   **Technology:** JavaScript runtime environment for Netlify Functions.
    *   **Rationale:** Widely used, large ecosystem, good performance for I/O-bound serverless workloads.
*   **Key Libraries:**
    *   `@supabase/supabase-js`: Client library for interacting with Supabase (database and RPCs).
    *   `jsonwebtoken`: Standard library for validating JWTs.
    *   `jwks-rsa`: Helper library to fetch public signing keys from Auth0's JWKS endpoint for JWT validation.

## 4. Security Architecture & Controls

*   **Authentication:**
    *   **Customer Authentication:** Handled by Auth0 (OAuth 2.0 / OIDC). Secure JWTs (signed with RS256) are issued upon successful login.
    *   **API Request Authentication:** Every protected API endpoint (Netlify Function) validates the incoming `Authorization: Bearer <JWT>` header.
    *   **JWT Validation Process:** Uses `jwks-rsa` to fetch the correct public key from Auth0 based on the token's `kid` header claim, then uses `jsonwebtoken` to verify the token's signature, audience (`AUTH0_AUDIENCE`), issuer (`AUTH0_DOMAIN`), and expiration (`exp`). Invalid tokens result in a `401 Unauthorized` response.
    *   **Machine-to-Machine (M2M) Authentication:** A specific API Key mechanism exists within `account-service` for trusted backend integrations. Keys are validated against Supabase, retrieving an associated `customerId` for authorization context.
*   **Authorization:**
    *   **Primary Mechanism:** Supabase Row Level Security (RLS) enforced directly at the database layer.
    *   **RLS Enforcement:** User context (Auth0 JWT `sub` claim or `customerId` from API Key lookup) is securely passed to the Supabase session using `SET session_replication_role = replica; SET "request.jwt.claims.sub" = '...'; SET session_replication_role = origin;` (or similar secure mechanism via the client library). RLS policies defined on tables (`customers`, `accounts`, `ledger_entries`) use this context (`current_setting('request.jwt.claims.sub', true)`) to permit or deny reads/writes, ensuring users only access their own data.
    *   **Function-Level Checks:** Service functions perform specific validation checks (e.g., validating request payloads). `transaction-service` verifies account ownership before initiating transfers, leveraging RLS implicitly during Supabase calls.
*   **Secrets Management:**
    *   All secrets (Supabase URL/Keys, Auth0 Domain/Audience, API Keys) are managed as Netlify Environment Variables.
    *   Secrets are scoped per Netlify deployment context (local development, deploy previews, production) and are **never** committed to the source code repository.
    *   The highly sensitive `SUPABASE_SERVICE_ROLE_KEY` usage is minimized; API requests are handled using user-scoped Supabase clients initialized with the validated JWT where possible to ensure RLS is enforced correctly.
*   **Data Protection:**
    *   **In Transit:** TLS 1.2+ enforced for all external connections (clients to Netlify, Netlify Functions to Supabase/Auth0).
    *   **At Rest:** Data is encrypted at rest by Supabase using standard mechanisms (e.g., AES-256).
    *   **PII Handling:** Sensitive PII (names, emails, potentially address/DOB in `customers` table) is stored within Supabase and protected primarily by RLS policies. No additional application-level encryption is currently implemented.
*   **Input Validation:** Netlify functions perform validation of request path parameters, query parameters, and request bodies to prevent common injection flaws and ensure data consistency.

## 5. Data Management & Integrity

*   **Database:** PostgreSQL (Managed by Supabase). ACID compliant.
*   **Core Data Models (See Annex A for DDL):**
    *   `customers`: Profile information, linked to `auth0_user_id`.
    *   `accounts`: Account details (type, status, currency), linked to `customer_id`. *Balance is not stored directly.*
    *   `ledger_entries`: Immutable double-entry ledger table. Records atomic debit/credit entries linked by `transaction_id`.
*   **Data Integrity Mechanisms:**
    *   **Atomic Ledger Operations:** Financial postings (debits/credits) are performed exclusively via the `post_ledger_transaction` PostgreSQL function (RPC) within Supabase. This function executes within a single database transaction, guaranteeing atomicity (all entries succeed or all fail).
    *   **Ledger Immutability:** The `ledger_entries` table is designed for immutability. Corrections are handled via reversing entries, not updates or deletes.
    *   **Dynamic Balance Calculation:** Account balances are calculated on-demand by the `calculate_balance` Supabase RPC function, summing relevant `DEBIT` and `CREDIT` entries from `ledger_entries`. This ensures balances always reflect the ledger state accurately.
    *   **Referential Integrity:** PostgreSQL foreign key constraints enforce relationships between tables (e.g., accounts belong to customers, ledger entries belong to accounts).
    *   **Database Constraints:** `CHECK` constraints (e.g., ledger amounts > 0) and `UNIQUE` constraints (e.g., `customers.auth0_user_id`, `accounts.account_number`) enforce data rules.

## 6. Core Business Processes (High-Level Flow)

*   **Customer Onboarding:**
    1.  User authenticates via Auth0.
    2.  Client application calls `POST /api/customer-service/customers` with the user's Auth0 JWT.
    3.  `customer-service` function validates JWT, extracts `sub` claim, creates a record in the `customers` table linking `auth0_user_id` to the `sub`.
*   **Account Creation:**
    1.  Authenticated user calls `POST /api/account-service/accounts` with JWT and desired account details (e.g., type).
    2.  `account-service` validates JWT, identifies associated `customer_id` (via RLS context), validates request, creates a record in the `accounts` table linked to the `customer_id`.
*   **Internal Funds Transfer:**
    1.  Authenticated user calls `POST /api/transaction-service/internal-transfer` with JWT and transfer details (fromAccountId, toAccountId, amount, currency).
    2.  `transaction-service` validates JWT, extracts `sub`.
    3.  It validates the request payload.
    4.  It performs an authorization check (implicitly relies on RLS/DB checks within the subsequent RPC call to ensure the user owns `fromAccountId`).
    5.  Generates a unique `transaction_id` (UUID).
    6.  Calls the `post_ledger_transaction` Supabase RPC with all details.
    7.  The RPC atomically performs validation (sufficient funds check on `fromAccountId` using `calculate_balance`), inserts the DEBIT entry into `ledger_entries`, inserts the CREDIT entry into `ledger_entries`.
    8.  `transaction-service` returns success/failure based on the RPC result.

## 7. Compliance Considerations (Current State)

*   **Security Best Practices:** Architecture incorporates standard security principles: secure authentication (JWT validation), fine-grained authorization (RLS), secure secrets management.
*   **Audit Trails:**
    *   **Auth0:** Provides detailed logs for identity events (logins, MFA, failures).
    *   **Netlify:** Provides basic function invocation logs (request/response metadata, `console.log` output).
    *   **Supabase:** Offers database-level logging capabilities (needs configuration for specific regulatory audit needs). PostgreSQL `log_statement` can capture executed queries.
    *   *Note:* A comprehensive, correlated audit trail across all components for regulatory purposes is not fully implemented in the prototype.
*   **Data Privacy (GDPR Principles):**
    *   **Data Minimization:** RLS enforces access control.
    *   **User Rights:** `customer-service` provides basic CRUD for user profiles. Deletion capability exists.
    *   *Note:* Explicit consent management mechanisms are not yet implemented.
*   **Disclaimer:** This prototype has not undergone formal mapping against specific financial regulations (e.g., PSD2 SCA, FAPI, PCI DSS, local banking laws). Integration of required AML/KYC processes is pending.

## 8. Testing & Quality Assurance

*   **Automated Testing:** Unit and integration tests implemented using Jest framework.
    *   **Scope:** Covers core logic within `customer-service`, `account-service`, and `transaction-service` functions.
    *   **Methodology:** Mocks external dependencies (`@supabase/supabase-js` client, `jsonwebtoken`, `jwks-rsa`) to test function logic in isolation and integration points. Tests cover success paths, error handling, authentication/authorization logic. Current target is high code coverage.
*   **Static Code Analysis:** ESLint is configured and used (`npm run lint`) to enforce code style and identify potential issues.
*   **CI/CD Integration:** Test execution (`npm test`) and linting (`npm run lint`) are defined as npm scripts, suitable for integration into the Netlify CI/CD pipeline to run automatically on commits/pull requests.

## 9. Deployment & Operations

*   **Deployment Model:** Continuous Deployment via Netlify's Git integration. Commits pushed to the main branch trigger automatic builds and deployments to the production environment. Pull requests generate isolated Deploy Previews.
*   **Environment Management:** Netlify Build Contexts (e.g., `production`, `deploy-preview`, `branch-deploy`) allow for environment-specific configurations, primarily managed via scoped Environment Variables.
*   **Infrastructure Management:** Infrastructure is largely managed by the service providers (Netlify, Supabase, Auth0). Configuration is managed via `netlify.toml` (build settings, redirects) and Supabase migrations.
*   **Database Schema Management:** Managed via Supabase Migrations using the Supabase CLI. Migration files are version-controlled in Git (`supabase/migrations`). Applying migrations to different environments is part of the deployment process.
*   **Monitoring (Current):** Relies on provider-specific dashboards and basic logging:
    *   Netlify Function logs.
    *   Supabase project monitoring (resource usage, query performance).
    *   Auth0 logs.
    *   *Note:* Comprehensive APM and business transaction monitoring/alerting are not yet configured.
*   **Rollbacks:** Netlify provides one-click instant rollbacks to previous successful deployments via its UI or CLI.

## 10. Risk Assessment Summary (High-Level - Prototype Phase)

*   **Security Risks:** Primary risks involve potential misconfiguration of Auth0, Supabase RLS policies, or vulnerabilities in dependencies.
    *   **Mitigation:** Strong JWT validation, strict RLS policies based on user context, secure environment variable management, planned dependency scanning.
*   **Operational Risks:** Risks include provider outages (Netlify, Supabase, Auth0) or performance degradation under load.
    *   **Mitigation:** Use of managed services with high availability SLAs, Netlify rollbacks, planned load testing and monitoring.
*   **Data Integrity Risks:** Risks include bugs in ledger RPC logic or failure during transaction processing.
    *   **Mitigation:** Use of PostgreSQL ACID transactions within RPCs, immutable ledger design, dynamic balance calculation, planned reconciliation processes.
*   **Compliance Risks:** Primary risk is launching without full adherence to all applicable financial regulations.
    *   **Mitigation:** Current adherence to security best practices. Requires dedicated compliance review, implementation of AML/KYC, detailed audit logging, and mapping to specific regulatory frameworks before launch.

## 11. Annexes

### Annex A: Core Data Model DDL

```sql
-- Located in supabase/migrations/...

-- ENUM Types
CREATE TYPE public.account_type_enum AS ENUM ('CHECKING', 'SAVINGS');
CREATE TYPE public.account_status_enum AS ENUM ('ACTIVE', 'DORMANT', 'PENDING_CLOSURE', 'CLOSED');
CREATE TYPE public.ledger_entry_type_enum AS ENUM ('DEBIT', 'CREDIT');
CREATE TYPE public.customer_status_enum AS ENUM ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'CLOSED');

-- customers table
CREATE TABLE public.customers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    auth0_user_id text NOT NULL UNIQUE,
    email text NOT NULL UNIQUE,
    full_name text NULL,
    date_of_birth date NULL,
    address jsonb NULL,
    status public.customer_status_enum NOT NULL DEFAULT 'PENDING_VERIFICATION'::public.customer_status_enum,
    kyc_status text NULL
);
-- Add indexes and RLS policies for customers...

-- accounts table
CREATE TABLE public.accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    customer_id uuid NOT NULL REFERENCES public.customers(id),
    account_number text NOT NULL UNIQUE,
    account_type public.account_type_enum NOT NULL,
    status public.account_status_enum NOT NULL DEFAULT 'ACTIVE'::public.account_status_enum,
    currency character(3) NOT NULL DEFAULT 'USD'::bpchar,
    nickname text NULL
);
-- Add indexes and RLS policies for accounts...

-- ledger_entries table
CREATE TABLE public.ledger_entries (
    id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    transaction_id uuid NOT NULL,
    account_id uuid NOT NULL REFERENCES public.accounts(id),
    entry_type public.ledger_entry_type_enum NOT NULL,
    amount numeric(19, 4) NOT NULL CHECK (amount > 0),
    currency character(3) NOT NULL,
    description text NULL
);
-- Add indexes and RLS policies for ledger_entries...

-- Supabase RPC Functions (Conceptual Signatures)
-- FUNCTION post_ledger_transaction(...) RETURNS void;
-- FUNCTION calculate_balance(p_account_id uuid) RETURNS numeric;
-- FUNCTION get_customer_id_for_api_key(p_api_key text) RETURNS uuid;
```

### Annex B: API Endpoint Summary

```
[Placeholder for detailed API Endpoint documentation]
(Should list paths, methods, required authentication (JWT/API Key), example request bodies, and responses for customer-service, account-service, transaction-service)

----------------------------------------------------
**Service:** transaction-service
**Endpoint:** POST /api/transaction-service/internal-transfer
**Authentication:** Auth0 JWT (Bearer Token) required.
**Authorization:** Implicit check via RLS that JWT subject owns `fromAccountId`.
**Request Body:**
{
  "fromAccountId": "uuid",
  "toAccountId": "uuid",
  "amount": number (e.g., 100.50),
  "currency": "string" (e.g., "USD"),
  "description": "string (optional)"
}
**Success Response (200 OK):**
{
  "message": "Transfer successful",
  "transactionId": "uuid" 
}
**Error Responses:** 400 (Invalid input), 401 (Auth failed), 403 (Permission denied), 404 (Source account not found), 422 (Insufficient funds), 500 (DB error)
----------------------------------------------------
**Service:** transaction-service
**Endpoint:** POST /api/transaction-service/transactions/external
**Authentication:** API Key (`X-API-Key` header) required.
**Authorization:** API Key must be valid and linked to a customer in the database.
**Request Body:**
{
  "accountId": "uuid",
  "amount": number (e.g., 50.00),
  "currency": "string" (e.g., "USD"),
  "description": "string",
  "externalReference": "string (optional)"
}
**Success Response (201 Created):**
// Returns the created ledger entry object
{
  "id": "le_uuid",
  "transaction_id": "txn_uuid",
  "account_id": "acc_uuid",
  "type": "DEPOSIT",
  "amount": 50.00,
  "currency": "USD",
  "description": "Deposit description",
  "external_reference": "optional_reference_string",
  "created_at": "timestamp"
}
**Error Responses:** 400 (Invalid input/RPC validation), 401 (Missing API Key), 403 (Invalid API Key), 404 (Account not found from RPC), 500 (DB error during auth or RPC)
----------------------------------------------------

[Add entries for customer-service and account-service here] 