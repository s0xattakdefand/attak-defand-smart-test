✅ Access Bypass: Types, Attacks, Defenses

| # | Type                     | Description                                              | Attack                                                        | Defense                                                       |
| - | ------------------------ | -------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------- |
| 1 | **Role Bypass**          | Circumventing `onlyOwner`, `hasRole()` checks            | Call from delegatecall or fallback to bypass access           | Strict modifier checks, `_msgSender()` context protection     |
| 2 | **Storage Bypass**       | Directly altering storage layout (e.g., slot collisions) | Write to role variables via delegatecall or `vm.store()`      | Use `keccak256` slot isolation + immutable guards             |
| 3 | **Proxy Admin Bypass**   | Misconfigured proxy admin logic                          | Upgrade contract or change admin without permission           | Enforce `upgradeTo` checks + EIP-1967 pattern                 |
| 4 | **Fallback Bypass**      | Unknown selector routes to fallback with dangerous logic | Call undefined selector to trigger fallback transfer or logic | Use `revert()` in fallback unless explicitly allowed          |
| 5 | **Signature Bypass**     | Replay or forge ECDSA signatures to impersonate users    | Replay signed metaTx or fake signer address                   | Use nonce + EIP-712 domain separators                         |
| 6 | **Init Function Bypass** | Initialization logic re-executed                         | Call `initialize()` on unprotected proxy logic                | Use `initializer` modifier and lock once                      |
| 7 | **External Hook Bypass** | Trigger reentrancy or privilege through hooks            | Use `onERC721Received` or callback to manipulate state        | Add reentrancy guard + deny external mutation in hook context |
