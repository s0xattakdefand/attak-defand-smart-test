🔢 Types of Selector Shadowing

| Type | Name                               | Description                                                                                                                                   |
| ---- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Accidental Selector Collision**  | Two different functions across contracts hash to the same selector (e.g., `transfer(address,uint256)` vs `burn(uint160,uint96)`).             |
| 2    | **Deliberate Selector Injection**  | Malicious contract defines function with intentionally colliding selector to hijack logic when called via `delegatecall` or proxy.            |
| 3    | **Shadowing via Inheritance**      | Child contract redefines a base contract function, shadowing the parent’s version — sometimes unintentionally.                                |
| 4    | **Interface Implementation Drift** | Contract claims to implement an interface, but selector matches a function with different logic or no access control.                         |
| 5    | **Fallback Selector Shadowing**    | Contract has `fallback()` that routes calls based on selector, and malicious code is triggered when unknown but colliding selectors are sent. |
| 6    | **Library Shadow Drift**           | Library functions injected into `delegatecall` share selectors with logic functions in the main contract.                                     |
| 7    | **Proxy Selector Overlap**         | Proxy calls route to implementation logic, but implementation has shadowed selectors not expected by the proxy's interface.                   |
| 8    | **Encoded Calldata Collisions**    | Contracts that parse raw calldata can be tricked into matching the wrong logic based on shared selector prefix.                               |
| 9    | **Encoding Drift via Frontends**   | Frontend ABI generates selectors that resolve to shadowed internal logic (e.g., Metamask signs calldata to unintended function).              |
| 10   | **Modifier-Based Selector Shift**  | Adding/removing modifiers in inherited contracts causes function position to shift in selector map, creating ABI desync.                      |
