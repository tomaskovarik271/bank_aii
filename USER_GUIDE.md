# Core Banking System - User Guide (Conceptual)

_Last Updated: 2024-08-01_

Welcome to the Core Banking System! This guide explains the features available to you.

**(Note:** This guide describes the intended functionality. As the system is currently API-based, a web or mobile application would be needed to interact with these features visually.)_

## Getting Started

1.  **Registration/Login:** You would first need to register and log in through our secure authentication provider (Auth0).
2.  **Profile Creation:** Upon first login, a basic customer profile is typically created for you automatically, linked to your login credentials.

## Core Features

### 1. Managing Your Profile (`Customer Service`)

*   **View Profile:** You can view your registered details, such as name and email address.
*   **Update Profile:** You can update certain profile information (like your name or email).
*   **(Future):** Functionality for updating address, date of birth, and completing Know Your Customer (KYC) verification would be added here.
*   **Delete Profile:** You have the option to delete your customer profile.

### 2. Managing Your Accounts (`Account Service`)

*   **Create Accounts:** You can open new accounts, such as:
    *   Checking Accounts
    *   Savings Accounts
    You can choose the currency for your account (e.g., USD, EUR) and optionally give it a nickname (e.g., "Holiday Fund").
*   **View Accounts:** You can see a list of all your accounts.
*   **View Account Details:** For each account, you can view:
    *   Account Number (a unique identifier)
    *   Account Type (Checking/Savings)
    *   Currency
    *   Nickname
    *   Current Balance
*   **Update Account Nickname:** You can change the nickname of an existing account.
*   **View Transaction History:** For any specific account, you can view a detailed history of all transactions (deposits, withdrawals, transfers).
*   **Delete Account:** You can close an account (provided it meets certain conditions, like having a zero balance and no recent activity - specific rules apply).

### 3. Moving Money (`Transaction Service`)

*   **Internal Transfers:** You can transfer funds between your own accounts (e.g., from Checking to Savings).
    *   You specify the account to transfer from, the account to transfer to, the amount, and currency.
    *   The system verifies you own the source account and checks for sufficient funds before processing the transfer.
    *   You receive a unique transaction ID for reference.
*   **(Future) External Deposits:** The system supports receiving deposits from external sources (like a linked bank account or a payment provider), although the user interface for initiating this would be part of a separate application.
*   **(Future) External Withdrawals/Payments:** Functionality for sending money outside the system would be added later.

## Security

*   Your login is secured by our identity provider (Auth0).
*   All communication with the banking services is encrypted.
*   Access to your accounts and profile information is strictly controlled based on your authenticated login. 