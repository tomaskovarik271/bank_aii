# Project Progress Tracker

## Phase 1: Setup & Basic Services

*   [x] Project Initialization (`npm init`, Git setup)
*   [x] Netlify CLI Setup & `netlify dev` working
*   [x] Supabase Project Setup
*   [x] Database Schema Definition (Initial: `customers`, `accounts`, `ledger_entries`)
*   [x] Auth0 Setup (M2M Application)
*   [x] Environment Variable Configuration (`.env`, Netlify UI)
*   [x] Basic `customer-service` Function (Create, Get /me)
*   [x] Basic `account-service` Function (Create, Get)
*   [x] Basic `transaction-service` Function (Status, Placeholder Transfer)
*   [x] Shared Utility Functions (`responseUtils.js`)
*   [x] JWT Authentication Middleware (including JWKS)

## Phase 2: Core Logic Implementation

*   [x] Database Functions/Triggers:
    *   [x] `post_ledger_transaction` RPC (Internal Transfer)
    *   [x] `calculate_balance` Function (Changed to VOLATILE)
    *   [x] `update_account_balance` Trigger
    *   [x] `get_my_customer_id` Helper Function (Corrected for non-UUID sub, SECURITY DEFINER)
    *   [x] `check_account_access` Helper Function (Created, SECURITY DEFINER)
    *   [x] `get_customer_id_for_api_key` RPC
    *   [x] `post_external_deposit` RPC
    *   [x] `get_account_transactions` RPC
*   [x] `customer-service` Implementation (Full CRUD - including PATCH/DELETE /me)
*   [x] `account-service` Implementation (Full CRUD - including Update/Delete, placeholder transactions)
*   [x] `transaction-service` Implementation:
    *   [x] `POST /internal-transfer` (using RPC)
    *   [x] `POST /transactions/external` (External Deposit, API Key Auth, using RPC)
*   [x] Row Level Security (RLS) Policies:
    *   [x] `customers` table (SELECT, INSERT, UPDATE, DELETE)
    *   [x] `accounts` table (SELECT, INSERT, UPDATE)
    *   [ ] `ledger_entries` table (RLS Disabled - Recommended)

## Phase 3: Testing & Refinement

*   [x] Unit Tests: 
    *   [x] Refactored Supabase mocks across all test suites for clarity and accuracy.
    *   [x] Fixed numerous unit test failures in `account-service` and `transaction-service` related to mocks and routing logic.
    *   [x] Implemented comprehensive unit tests for `customer-service` covering all current endpoints and logic paths.
    *   [x] `account-service` (Covering existing CRUD)
    *   [x] `transaction-service` (Covering Status, Internal Transfer, External Deposit)
    *   **Note:** All core services now have foundational unit tests.
*   [x] Integration Tests: (Core flow implemented)
    *   [x] Customer verification & Account Creation flow (`tests/integration/core-flow.test.js`).
    *   [ ] Transfer & Balance Verification flow (**Skipped**: Requires deposit first).
    *   [ ] Error handling / Edge cases.
*   [x] Manual API Testing (`TESTING.md`):
    *   DEPRECATED: Manual test file removed in favor of automated tests.
*   [x] API Documentation (Refine comments)
    *   **Done:** Refined JSDoc comments in `customer-service`, `account-service`, and `transaction-service`.
    *   **Deferred:** Formal OpenAPI specification generation.
*   [ ] Error Handling Improvements
*   [ ] Logging Improvements

## Phase 3: Pre-Launch Hardening & Readiness Plan

**Goal:** Address critical compliance, security, operational, and architectural requirements necessary to move the prototype towards a state suitable for live, regulated banking operations. This phase focuses on foundational hardening **before** implementing significant new banking features.

**Status:** Not Started

### 3.1 Compliance & Legal Foundation

*   `[ ]` **Engage Legal & Compliance Experts:** Secure specialized counsel for FinTech/Banking regulations in target jurisdictions.
*   `[ ]` **Identify Specific Regulations:** Complete detailed mapping of all applicable laws (AML/CFT, KYC, GDPR/CCPA, PSD2/Open Banking, Consumer Protection, Local Banking Acts).
*   `[ ]` **Banking License Application:** Initiate the formal application process(es).
*   `[ ]` **KYC/AML Vendor Selection & Integration Plan:** Evaluate and select KYC/AML service provider(s). Plan technical integration.
*   `[ ]` **Draft & Vet User Agreements:** Create and obtain legal approval for Terms of Service, Privacy Policy, and any other required customer agreements.
*   `[ ]` **Regulatory Reporting Requirements:** Define specific data points and formats required for regulatory reports.

### 3.2 Security Hardening & Verification

*   `[ ]` **Implement Static & Dynamic Security Testing (SAST/DAST):** Integrate automated security scanning tools into the CI/CD pipeline.
*   `[ ]` **Implement Software Composition Analysis (SCA):** Integrate dependency vulnerability scanning into the CI/CD pipeline.
*   `[ ]` **Harden IAM Configurations:**
    *   `[ ]` Review and enforce stricter Auth0 policies (MFA, password complexity, session timeouts, risky login detection).
    *   `[ ]` Review and minimize Supabase role permissions. Further restrict `service_role` key usage.
    *   `[ ]` Define and implement access control policies for internal staff.
*   `[ ]` **Implement WAF & DDoS Protection:** Configure and tune Web Application Firewall rules and review DDoS mitigation strategy.
*   `[ ]` **Comprehensive Audit Logging:**
    *   `[ ]` Design detailed audit log requirements (what events, data fields, format).
    *   `[ ]` Implement enhanced logging within Netlify Functions for key actions.
    *   `[ ]` Configure Supabase database logging appropriately (e.g., using `pgAudit` extension or triggers).
    *   `[ ]` Plan for secure, tamper-evident log aggregation and retention.
*   `[ ]` **Schedule Third-Party Penetration Test:** Engage external security firm for testing *after* initial hardening tasks are complete.
*   `[ ]` **Remediate Pen Test Findings:** Address all vulnerabilities identified during penetration testing.

### 3.3 Operational Readiness

*   `[ ]` **Implement Comprehensive Monitoring & Alerting:**
    *   `[ ]` Select and integrate APM tool for Netlify Functions.
    *   `[ ]` Configure detailed Supabase monitoring (resource usage, query performance, replication lag).
    *   `[ ]` Set up monitoring for key business metrics (e.g., transfer success rates, API error rates).
    *   `[ ]` Configure actionable alerting for critical events (failures, security alerts, performance thresholds).
*   `[ ]` **Define Service Level Objectives (SLOs):** Establish measurable targets for uptime and performance.
*   `[ ]` **Develop Incident Response Plan:** Document procedures for handling security incidents and operational outages.
*   `[ ]` **Develop & Test Disaster Recovery / Backup Plan:**
    *   `[ ]` Verify Supabase backup strategy.
    *   `[ ]` Document restore procedures.
    *   `[ ]` Conduct periodic restore tests.
    *   `[ ]` Define RTO/RPO.

### 3.4 Architectural Refinement (Asynchronicity)

*   `[ ]` **Evaluate & Select Asynchronous Processing Mechanism:** Confirm if Inngest is the chosen solution or evaluate alternatives if necessary.
*   `[ ]` **Refactor Internal Transfer Flow:** Modify `transaction-service` to use the chosen asynchronous mechanism (e.g., publish an event/job) instead of calling the ledger RPC directly within the API request handler. Implement corresponding worker/handler logic.
*   `[ ]` **Identify Other Candidates for Asynchronous Processing:** Review if other actions (e.g., future notifications, report generation) should also be made asynchronous.

### 3.5 Core Process Enhancements

*   `[ ]` **Integrate KYC/AML Vendor:** Implement API calls and workflows for customer identity verification during onboarding, based on vendor selection in 3.1.
*   `[ ]` **Implement Ledger Reconciliation:** Develop automated checks/scripts to verify ledger integrity (e.g., total debits == total credits, account balances match summed ledger entries).
*   `[ ]` **Design & Implement Basic Fraud Detection:** Implement initial rules and monitoring for suspicious transaction patterns.

### 3.6 Documentation & Reporting Finalization

*   `[ ]` **Complete API Endpoint Documentation:** Fill in Annex B of `CENTRAL_BANK_REGULATORY_OVERVIEW.md`.
*   `[ ]` **Create Architecture Diagrams:** Add required diagrams to documentation (`CENTRAL_BANK_REGULATORY_OVERVIEW.md`, potentially `SYSTEM_DOCUMENTATION.md`).
*   `[ ]` **Prepare Initial Regulatory Submissions:** Collate required documentation based on compliance track (3.1).

**Immediate Next Steps Focus:** Initiate Phase 3.1 (Compliance & Legal) as it underpins everything. Begin parallel work on Phase 3.2 (Security Hardening - initial steps like SAST/SCA/IAM review) and Phase 3.3 (Operational Readiness - monitoring setup).

## Phase 4: Advanced Features (Future)

*   [ ] User Authentication (Frontend integration)
*   [ ] KYC/Customer Verification Flow
*   [ ] Implement `GET /accounts/{id}/transactions` in `account-service`.
*   [ ] Different Transaction Types (e.g., External Withdrawals)
*   [ ] API Key Management for External Partners (Further Enhancements)
*   [ ] Currency Conversion
*   [ ] Notifications Service

## Known Issues / TODOs

*   Review `VOLATILE` status of `calculate_balance` function - ensure it meets performance needs.
*   Implement proper Update/Delete logic in services (if not already covered by CRUD).
*   Add integration tests for Transfer & Balance Verification flow (requires deposit mechanism).
*   Add more integration tests for error handling / edge cases.
*   Address pending TODOs in Phase 3 (Error Handling, Logging).
*   Begin work on Phase 3 (Pre-Launch Hardening).