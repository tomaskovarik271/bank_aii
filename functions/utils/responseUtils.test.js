const { createJsonResponse } = require('./responseUtils');

describe('createJsonResponse Utility', () => {

    it('should create a valid JSON response structure', () => {
        const statusCode = 200;
        const body = { message: 'Success', data: [1, 2, 3] };
        const expectedResponse = {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        };

        const actualResponse = createJsonResponse(statusCode, body);
        
        expect(actualResponse).toEqual(expectedResponse);
    });

    it('should correctly stringify the body', () => {
        const statusCode = 400;
        const body = { error: 'Bad Request' };
        
        const actualResponse = createJsonResponse(statusCode, body);

        expect(actualResponse.body).toBe(JSON.stringify(body));
        expect(typeof actualResponse.body).toBe('string');
    });

    it('should set the correct statusCode', () => {
        const statusCode = 500;
        const body = { error: 'Server Error' };
        
        const actualResponse = createJsonResponse(statusCode, body);

        expect(actualResponse.statusCode).toBe(statusCode);
    });

     it('should set the correct headers', () => {
        const statusCode = 201;
        const body = { id: '123' };
        
        const actualResponse = createJsonResponse(statusCode, body);

        expect(actualResponse.headers).toEqual({ 'Content-Type': 'application/json' });
    });

}); 