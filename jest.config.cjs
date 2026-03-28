/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.ts'],
  // Resolve .js extension imports to their .ts source files
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  globals: {
    'ts-jest': {
      tsconfig: {
        // Use CommonJS for tests to avoid ESM/jest complexity
        module: 'CommonJS',
        moduleResolution: 'Node',
        esModuleInterop: true,
        resolveJsonModule: true,
        strict: true,
        // Tests may have intentional unused imports in mocks
        noUnusedLocals: false,
        noUnusedParameters: false,
        target: 'ES2022',
        lib: ['ES2022'],
      },
    },
  },
};
