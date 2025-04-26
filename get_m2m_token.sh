# Get token (copy access_token from response)
curl --request POST \
    --url "https://dev-as7b38p8c1wmdva4.us.auth0.com/oauth/token" \
    --header 'content-type: application/json' \
    --data '{ "client_id": "eTLPOIuXrJT6NZaeIGh1ygkZdVLxxZoG", "client_secret": "eYHyAG0jT3XSC1URB09Z7ZB_mDv-8SxjtAstII7M9fAHWF5ayxlYXb1ettb-4-uX", "audience": "https://api.core-banking-ai", "grant_type": "client_credentials" }'

# Export token (paste value)
export M2M_TOKEN="<PASTE_YOUR_COPIED_M2M_ACCESS_TOKEN_HERE>"