🔢 Types of Role Configuration

| Type | Name                               | Description                                                                                   |
| ---- | ---------------------------------- | --------------------------------------------------------------------------------------------- |
| 1    | **Static Role Configuration**      | Roles are hardcoded and cannot change (e.g., `owner`, `admin` set in constructor).            |
| 2    | **Dynamic Role Assignment**        | Roles can be added/removed at runtime using functions like `grantRole` / `revokeRole`.        |
| 3    | **Hierarchical Roles**             | Roles are structured in parent-child hierarchy (e.g., `superAdmin` > `admin` > `user`).       |
| 4    | **Multi-Signature Roles**          | Roles are exercised only when multiple addresses approve (e.g., Gnosis Safe-style multisigs). |
| 5    | **Time-Locked Roles**              | Roles are only active after a certain time or block (e.g., governance delay).                 |
| 6    | **Rotating / Epoch-Based Roles**   | Roles rotate over time (e.g., validator roles per epoch in consensus).                        |
| 7    | **Role via Token Ownership**       | Role is based on NFT or ERC20 ownership (e.g., "Only token holders can vote").                |
| 8    | **Hashed Role Commitments**        | Roles are committed via hashed secrets or signatures (e.g., zk-based identity).               |
| 9    | **Delegated Roles**                | Roles can be delegated temporarily or with conditions to another address.                     |
| 10   | **Role Bundles / Composite Roles** | Multiple roles grouped into one meta-role (e.g., `OPERATOR` = `PAUSER + UPGRADER`).           |
