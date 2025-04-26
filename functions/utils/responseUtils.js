// functions/utils/responseUtils.js

function createJsonResponse(statusCode, body) {
    return {
        statusCode: statusCode,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    };
}

module.exports = {
    createJsonResponse,
}; 