# vcrypt development guide

These instructions apply to all code under `vcrypt/`.

## Tests

Use `Test_privateBackend_Sign` in `backend/rsa/backend.private_test.go` as the canonical test pattern.

Tests must:

- define one test function per production function or method, named after the subject under test, for example `Test_privateBackend_Sign`;
- keep all cases for that function or method in a single table-driven `tests` slice;
- include both successful and relevant failure cases in that table;
- execute every table entry as a named subtest with `t.Run`;
- define test-local assertion functions for distinct outcomes, such as a valid result or an expected error;
- store the appropriate assertion function in each table entry and invoke it from the shared test runner; and
- keep setup values grouped by purpose before the assertions and test table so cases remain compact and readable.

Assertion functions should validate the complete outcome, including returned errors and result correctness. For cryptographic operations, independently verify successful output with the appropriate standard-library primitive when practical.
