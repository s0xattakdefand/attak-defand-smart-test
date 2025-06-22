🔢 Types of Gas Bomb Passes

| Type | Name                             | Description                                                                                                                      |
| ---- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Loop Bomb Pass**               | A user passes data (e.g., large arrays) that triggers an unbounded loop (`for`, `while`) and runs out of gas.                    |
| 2    | **Delegatecall Gas Bomb**        | A delegated contract executes code with gas-heavy operations — consuming caller gas quota.                                       |
| 3    | **Reentrancy Depth Bomb**        | Recursive fallback calls drain gas without reentrancy protection, leading to stack exhaustion or partial reverts.                |
| 4    | **Event Logging Bomb**           | Emitting large logs or `indexed` parameters on-chain to exhaust gas during normal state transitions.                             |
| 5    | **Storage Write Bomb**           | Contract triggers expensive SSTORE or nested struct writes that exceed block gas limit.                                          |
| 6    | **External Call Bomb**           | External contract call is crafted to consume max gas while appearing valid (e.g., `call.value().gas()` without return check).    |
| 7    | **Constructor Gas Bomb**         | A contract is deployed with a constructor that performs gas-intensive work and gets passed to logic contracts.                   |
| 8    | **ABI Decode Bomb**              | Calldata contains large or deeply nested data that causes `abi.decode()` to consume excessive gas.                               |
| 9    | **Calldata Bomb**                | Large calldata that triggers gas overflow in parsing logic, especially in proxy/fallback routers.                                |
| 10   | **Fallback Selector Drift Bomb** | Unknown selector routes to `fallback()` which contains dynamic logic like looping over stored state or calling external modules. |
