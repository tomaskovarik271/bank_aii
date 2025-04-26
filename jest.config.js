// jest.config.js
module.exports = {
  // Look for test files in functions/**/ and tests/**/
  testMatch: [
    "**/functions/**/*.test.js",
    "**/tests/**/*.test.js"
  ],
  // Ignore node_modules
  testPathIgnorePatterns: [
    "/node_modules/"
  ],
  // Optional: Set the environment (Node.js for backend tests)
  testEnvironment: 'node',
  // Optional: Clear mocks between tests
  clearMocks: true,
}; 