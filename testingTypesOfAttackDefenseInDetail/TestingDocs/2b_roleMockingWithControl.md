🔢 Types of Role Mocking with Control

| Type | Name                                      | Description                                                                                                          |
| ---- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 1    | **Prank Role Injection (Testing)**        | Using `vm.prank()` or `hoax()` to impersonate privileged roles in test scenarios.                                    |
| 2    | **Mock Modifier Bypass**                  | Mocking the `onlyRole` or `onlyOwner` modifiers by overriding the role check function.                               |
| 3    | **Signature-Based Role Mocking**          | Forging or replaying valid signatures to impersonate signers with roles (used in MetaTx, DAOs, multisigs).           |
| 4    | **Delegatecall Role Masking**             | A delegatecalled contract uses `msg.sender`, but the actual control logic is in the caller — allowing spoofed roles. |
| 5    | **Constructor Role Seeding**              | A contract is deployed with constructor-embedded roles, which are later hijacked by a mocking deployer.              |
| 6    | **Zero-Address Role Mocking**             | Contracts with weak role guards default to `address(0)` being implicitly allowed.                                    |
| 7    | **Fake Interface Implementation**         | A mock contract returns `true` for role-check functions like `hasRole(bytes32,address)` regardless of actual roles.  |
| 8    | **Immutable Role Confusion**              | Contract stores immutable role addresses in variables that are mocked during deployment tests.                       |
| 9    | **Role Flag Injection via Storage Drift** | Storage collision or drift enables a fake contract to set role flags in overlapping storage slots.                   |
| 10   | **Cross-Chain Role Spoofing**             | Relayers or cross-chain bridges inject control messages pretending to be from valid role addresses.                  |


