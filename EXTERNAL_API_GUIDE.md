# Core Banking System - External API Guide (API Key)

_Last Updated: 2024-08-01_

This guide provides details for external systems integrating with the Core Banking System using API Key authentication.

## 1. Authentication

*   **Method:** API Key
*   **Mechanism:** Include your assigned API Key in the `X-API-Key` HTTP header on every request.
    ```http
    X-API-Key: YOUR_ASSIGNED_API_KEY
    ```
*   **Security:** Keep your API key confidential. It grants permission to perform specific actions (like deposits) on behalf of the associated customer/entity.
*   **Validation:** The system validates the API key using the `get_customer_id_for_api_key` database function. Invalid or missing keys will result in a `401 Unauthorized` or `403 Forbidden` error.

## 2. Available Endpoints

### 2.1. External Deposit

*   **Endpoint:** `POST /api/transaction-service/transactions/external`
*   **Purpose:** Allows a trusted external system to deposit funds into a specific customer account.
*   **Request Body:**
    ```json
    {
      "accountId": "uuid",              // Required: The target account ID (UUID format)
      "amount": number,               // Required: The positive amount to deposit
      "currency": "string",           // Required: 3-letter currency code (e.g., "USD", "EUR")
      "description": "string",        // Required: Description of the deposit (e.g., "Payment Received")
      "externalReference": "string"   // Optional: A reference ID from the external system (e.g., Charge ID)
    }
    ```
*   **Responses:**
    *   **`201 Created`**: Deposit successful. The response body contains the created ledger entry object.
        ```json
        // Example Success Response Body
        {
          "id": "le_uuid_generated_by_db",
          "transaction_id": "txn_uuid_generated_by_db",
          "account_id": "uuid_from_request",
          "type": "DEPOSIT",
          "amount": 100.50, // Amount from request
          "currency": "USD",  // Currency from request
          "description": "Deposit description", // Description from request
          "external_reference": "optional_reference_string", // Ref from request
          "created_at": "timestamp"
        }
        ```
    *   **`400 Bad Request`**: Invalid request body (missing fields, wrong types) OR validation error from the database RPC (e.g., account inactive, currency mismatch). The `message` field in the response body provides details.
        ```json
        // Example 400 Response Body (Validation Error)
        {
          "message": "Validation Error: Currency mismatch: Expected USD got EUR"
        }
        ```
        ```json
        // Example 400 Response Body (Input Error)
        {
          "message": "Missing or invalid required field type: amount (must be a number)"
        }
        ```
    *   **`401 Unauthorized`**: `X-API-Key` header is missing.
        ```json
        {
          "message": "Missing API Key"
        }
        ```
    *   **`403 Forbidden`**: The provided API Key is invalid or expired.
        ```json
        {
          "message": "Forbidden: Invalid API Key"
        }
        ```
    *   **`404 Not Found`**: The specified `accountId` does not exist (determined by the database RPC).
        ```json
        {
          "message": "Validation Error: Account not found: <accountId>"
        }
        ```
    *   **`500 Internal Server Error`**: An unexpected error occurred during API key validation or processing the deposit RPC.
        ```json
        {
          "message": "Database error processing deposit."
        }
        ```
        ```json
        // Or during key validation
        {
          "message": "Database error verifying API key."
        }
        ```

### 2.2. Account Read Operations (Optional)

Depending on permissions granted to the API Key, it *may* also be possible to use the key for certain read operations in the `account-service`:

*   `GET /api/account-service/accounts`: List accounts associated with the API key's customer.
*   `GET /api/account-service/accounts/{accountId}`: Get details for a specific accessible account.
*   `GET /api/account-service/accounts/{accountId}/transactions`: Get transactions for a specific accessible account.

Refer to the main `API_REFERENCE.md` for details on these endpoints, but remember to use the `X-API-Key` header instead of `Authorization: Bearer`. Access control is enforced via database checks based on the customer linked to the API key. 