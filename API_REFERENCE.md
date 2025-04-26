# Core Banking System - API Reference

_Last Updated: 2024-08-01_

This document provides technical details for developers using the Core Banking System API.

## 1. Base URL

All API endpoints are relative to the base URL provided by the Netlify deployment. For local development using `netlify dev`, the base URL is typically `http://localhost:8888`.

The API endpoints follow the pattern: `/api/<service-name>/<resource-path>`

Example: `http://localhost:8888/api/customer-service/me`

## 2. Authentication

The API uses two primary authentication methods:

*   **JWT (JSON Web Token):** Used for operations initiated by end-users (customers).
    *   **Mechanism:** Pass an Auth0-issued JWT in the `Authorization` header.
    *   **Format:** `Authorization: Bearer <your_jwt_token>`
    *   **Validation:** Functions validate the JWT signature, audience, and issuer against Auth0 configuration. The user's identity (`sub` claim) is used for authorization checks (RLS).
    *   **Used By:** Most endpoints in `customer-service`, `account-service`, and `transaction-service`'s `/internal-transfer`.
*   **API Key:** Used for operations initiated by trusted external systems (e.g., payment gateways).
    *   **Mechanism:** Pass a pre-shared API key in the `X-API-Key` header.
    *   **Format:** `X-API-Key: <your_api_key>`
    *   **Validation:** Functions validate the API key against the database using the `get_customer_id_for_api_key` RPC. The associated `customer_id` is used for authorization.
    *   **Used By:** `transaction-service`'s `/transactions/external`, and potentially some read operations in `account-service`.

## 3. Services and Endpoints

### 3.1. `customer-service`

Manages customer profiles. Requires **JWT Authentication** for all endpoints.

*   **`GET /api/customer-service/me`**
    *   **Description:** Retrieves the profile of the currently authenticated customer.
    *   **Responses:**
        *   `200 OK`: Customer profile object.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `404 Not Found`: Customer profile does not exist for this user.
        *   `500 Internal Server Error`: Database error.
*   **`POST /api/customer-service/`**
    *   **Description:** Creates a new customer profile linked to the authenticated user.
    *   **Request Body:** `{ "email": "string", "full_name": "string" }`
    *   **Responses:**
        *   `201 Created`: Newly created customer profile object.
        *   `400 Bad Request`: Missing required fields in body.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `409 Conflict`: Customer profile already exists for this user.
        *   `500 Internal Server Error`: Database error.
*   **`PATCH /api/customer-service/me`**
    *   **Description:** Updates the profile details (name, DOB, address) for the authenticated user. (Note: Only name/email update tested, others might need schema/code changes).
    *   **Request Body:** `{ "full_name": "optional string", "email": "optional string", ... }`
    *   **Responses:**
        *   `200 OK`: Updated customer profile object.
        *   `400 Bad Request`: Invalid fields in body.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `404 Not Found`: Customer profile does not exist.
        *   `500 Internal Server Error`: Database error.
*   **`DELETE /api/customer-service/me`**
    *   **Description:** Deletes the customer profile for the authenticated user.
    *   **Responses:**
        *   `204 No Content`: Successful deletion.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `404 Not Found`: Customer profile does not exist.
        *   `500 Internal Server Error`: Database error.

### 3.2. `account-service`

Manages bank accounts and transaction history. Supports **JWT or API Key Authentication** for read operations, **JWT only** for write/delete operations.

*   **`POST /api/account-service/accounts`**
    *   **Auth:** JWT only.
    *   **Description:** Creates a new bank account (CHECKING or SAVINGS).
    *   **Request Body:** `{ "account_type": "CHECKING" | "SAVINGS", "currency": "USD" | "EUR" | ..., "nickname": "optional string" }`
    *   **Responses:**
        *   `201 Created`: Newly created account object.
        *   `400 Bad Request`: Invalid input body.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `403 Forbidden`: Customer profile required but not found for JWT user.
        *   `500 Internal Server Error`: Database error.
*   **`GET /api/account-service/accounts`**
    *   **Auth:** JWT or API Key.
    *   **Description:** Lists all accounts associated with the authenticated customer.
    *   **Responses:**
        *   `200 OK`: Array of account objects.
        *   `401 Unauthorized`: Invalid/missing JWT or API Key.
        *   `500 Internal Server Error`: Database error.
*   **`GET /api/account-service/accounts/{accountId}`**
    *   **Auth:** JWT or API Key.
    *   **Description:** Retrieves details for a specific account, including the calculated balance. Authorization checked via `check_account_access` RPC.
    *   **Responses:**
        *   `200 OK`: Account object with balance details.
        *   `400 Bad Request`: Invalid `accountId` format.
        *   `401 Unauthorized`: Invalid/missing JWT or API Key.
        *   `403 Forbidden`: Access denied to this account.
        *   `404 Not Found`: Account not found or access denied.
        *   `500 Internal Server Error`: Database error.
*   **`PATCH /api/account-service/accounts/{accountId}`**
    *   **Auth:** JWT only.
    *   **Description:** Updates the nickname of a specific account. Authorization checked via `check_account_access` RPC.
    *   **Request Body:** `{ "nickname": "string" }`
    *   **Responses:**
        *   `200 OK`: Updated account object.
        *   `400 Bad Request`: Invalid `accountId` format or missing nickname.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `403 Forbidden`: Access denied to this account.
        *   `404 Not Found`: Account not found or access denied.
        *   `500 Internal Server Error`: Database error.
*   **`DELETE /api/account-service/accounts/{accountId}`**
    *   **Auth:** JWT only.
    *   **Description:** Deletes a specific account. Authorization checked via `check_account_access` RPC.
    *   **Responses:**
        *   `204 No Content`: Successful deletion.
        *   `400 Bad Request`: Invalid `accountId` format.
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `403 Forbidden`: Access denied to this account.
        *   `404 Not Found`: Account not found or access denied.
        *   `500 Internal Server Error`: Database error (e.g., if account has transactions - FK constraint).
*   **`GET /api/account-service/accounts/{accountId}/transactions`**
    *   **Auth:** JWT or API Key.
    *   **Description:** Retrieves the transaction history (ledger entries) for a specific account. Authorization checked via `check_account_access` RPC.
    *   **Responses:**
        *   `200 OK`: Array of ledger entry objects.
        *   `400 Bad Request`: Invalid `accountId` format.
        *   `401 Unauthorized`: Invalid/missing JWT or API Key.
        *   `403 Forbidden`: Access denied to this account.
        *   `404 Not Found`: Account not found or access denied.
        *   `500 Internal Server Error`: Database error.

### 3.3. `transaction-service`

Handles money movement. Uses JWT for user-initiated transfers and API Key for external deposits.

*   **`GET /api/transaction-service/status`**
    *   **Auth:** JWT required.
    *   **Description:** Simple health check.
    *   **Responses:** `200 OK`: `{ "status": "OK" }`.
*   **`POST /api/transaction-service/internal-transfer`**
    *   **Auth:** JWT required.
    *   **Description:** Executes a transfer between two accounts owned by the authenticated user. Uses `post_ledger_transaction` RPC.
    *   **Request Body:** `{ "fromAccountId": "uuid", "toAccountId": "uuid", "amount": number, "currency": "string", "description": "optional string" }`
    *   **Responses:**
        *   `200 OK`: `{ "message": "Transfer successful", "transactionId": "uuid" }`
        *   `400 Bad Request`: Invalid input (validation checks).
        *   `401 Unauthorized`: Invalid/missing JWT.
        *   `403 Forbidden`: User does not own `fromAccountId`.
        *   `404 Not Found`: `fromAccountId` not found.
        *   `422 Unprocessable Entity`: Insufficient funds (RPC error `P0001`).
        *   `500 Internal Server Error`: Other database/RPC error.
*   **`POST /api/transaction-service/transactions/external`**
    *   **Auth:** API Key required (`X-API-Key`).
    *   **Description:** Allows an external system to deposit funds into an account. Uses `post_external_deposit` RPC.
    *   **Request Body:** `{ "accountId": "uuid", "amount": number, "currency": "string", "description": "string", "externalReference": "optional string" }`
    *   **Responses:**
        *   `201 Created`: Ledger entry object created by the deposit.
        *   `400 Bad Request`: Invalid input or RPC validation error (e.g., inactive account, currency mismatch).
        *   `401 Unauthorized`: Missing API Key.
        *   `403 Forbidden`: Invalid API Key.
        *   `404 Not Found`: `accountId` not found (RPC error).
        *   `500 Internal Server Error`: Database/RPC error.

## 4. Error Responses

Standard HTTP status codes are used. Error responses generally follow this format:

```json
{
  "message": "Descriptive error message",
  "errors": [ // Optional: Array of specific validation errors
    "Detailed error 1",
    "Detailed error 2"
  ],
  "code": "OPTIONAL_ERROR_CODE", // e.g., INSUFFICIENT_FUNDS
  "transactionId": "optional_uuid" // Included for transfer errors
}
``` 