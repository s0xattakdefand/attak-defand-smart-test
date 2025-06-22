✅ Types of Test Injection Attacks in Web3/Smart Contracts

| Type | Name                           | Description                                                                                                                        |
| ---- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Assertion Injection**        | Injecting false conditions to force test pass or bypass logic (e.g., `assert(x == 1)` is injected or overridden).                  |
| 2    | **Hook Injection**             | Injecting malicious logic into pre/post hooks used in testing or contract setup (e.g., Forge's `setUp()` or Foundry cheatcodes).   |
| 3    | **Constructor Test Injection** | Injecting state or Ether during constructor logic using test framework loopholes (e.g., via `vm.prank()` or `create2`).            |
| 4    | **Mock/Stub Injection**        | Injecting fake return values in mocks to cause the contract under test to behave insecurely.                                       |
| 5    | **EVM Opcode Injection**       | Using inline assembly or `cheatcodes` to inject test-specific EVM behavior like `gasleft()`, `block.number`, or time manipulation. |
| 6    | **Storage Injection**          | Altering storage slots directly using cheatcodes (e.g., `vm.store`) to bypass guards or simulate state drift.                      |
| 7    | **Revert Bypass Injection**    | Overriding function selectors or expected reverts in test conditions to cause false positives.                                     |
| 8    | **Trace/Log Injection**        | Injecting fake logs or trace events to falsify test coverage, execution path, or simulate incorrect state.                         |
