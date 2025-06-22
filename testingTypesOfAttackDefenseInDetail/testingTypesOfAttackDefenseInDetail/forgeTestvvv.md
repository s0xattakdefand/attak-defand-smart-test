| Feature                       | Meaning                                                                    |
| ----------------------------- | -------------------------------------------------------------------------- |
| `Compiling...`                | Compiles all contracts and tests with `solc` (v0.8.29 here)                |
| `Ran X tests for ...`         | Lists how many test functions ran per `.t.sol` file                        |
| `[PASS] testName()`           | Individual test result and gas usage per function                          |
| `testFuzz_SetNumber(uint256)` | Indicates a **fuzz test** (auto-generated inputs) and how many runs it did |
| `μ:` and `~:`                 | Average gas used (`μ`) and approximate max (`~`) for fuzzed inputs         |
| `Suite result`                | Summary per test contract (number passed/failed/skipped)                   |
| `finished in X ms/µs`         | Shows how fast each test suite finished (real vs CPU time)                 |
| `Ran X test suites...`        | Final summary of all tests run across all files                            |
