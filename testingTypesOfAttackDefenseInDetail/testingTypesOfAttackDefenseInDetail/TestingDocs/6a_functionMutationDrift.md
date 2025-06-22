🔢 Types of Function Mutation Drift

| Type | Name                            | Description                                                                                                                                                      |
| ---- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Logic Mutation Drift**        | Core logic is changed but function selector remains the same (e.g., `transfer()` now burns tokens).                                                              |
| 2    | **Selector Collision Drift**    | Two different functions in two contracts map to the same 4-byte selector but do different things.                                                                |
| 3    | **ABI-Compatible Drift**        | Function keeps the same name/signature, but internal logic changes silently (e.g., adds a new role check, changes math formula).                                 |
| 4    | **Inherited Function Drift**    | A base contract defines a function, and a child overrides it with different behavior.                                                                            |
| 5    | **Proxy Upgrade Drift**         | Upgraded implementation changes behavior of an existing function, even though the ABI and address remain constant.                                               |
| 6    | **Shadow Fallback Drift**       | Function logic is moved from named functions into `fallback()` or `receive()`, breaking expectations.                                                            |
| 7    | **External Call Drift**         | Internal logic uses an external contract call, and that external contract mutates its behavior (e.g., governance delegate changes `logic.execute()`).            |
| 8    | **ZK or Signature-Gated Drift** | Function begins enforcing new gates (zkProof, metaTx, RSA checks) without changing external ABI.                                                                 |
| 9    | **Function Modifier Drift**     | A function gets or loses a modifier (`onlyOwner`, `whenNotPaused`, etc.) over time.                                                                              |
| 10   | **Argument Semantics Drift**    | Function argument names and types remain the same, but **what the function *does*** with them changes (e.g., `amount` now means fee instead of transfer amount). |
