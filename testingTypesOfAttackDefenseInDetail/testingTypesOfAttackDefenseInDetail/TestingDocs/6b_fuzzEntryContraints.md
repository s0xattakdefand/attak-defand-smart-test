🔢 Types of Fuzz Entry Constraints

| Type | Name                              | Description                                                                                                       |
| ---- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 1    | **Selector Constraints**          | Restrict fuzzing to specific function selectors (`0xdeadbeef`, `deposit()`, `claim()`) instead of arbitrary ones. |
| 2    | **Role/Access Constraints**       | Enforce fuzzed calls to simulate specific caller roles (e.g., onlyOwner, admin, user).                            |
| 3    | **State Snapshot Constraints**    | Fuzz only when the contract is in a defined state (e.g., `paused == false`, `roundStarted == true`).              |
| 4    | **Value Constraints**             | Constrain ETH/msg.value sent during fuzzing (e.g., between 1 wei and 1 ETH).                                      |
| 5    | **Gas Constraints**               | Apply gas limits or min gas caps to simulate resource exhaustion or failure thresholds.                           |
| 6    | **Argument Shape Constraints**    | Enforce argument types or patterns (e.g., only fuzz arrays with `len <= 10`, or addresses ≠ `0x0`).               |
| 7    | **Path Depth Constraints**        | Restrict call depth or recursive entry (used in detecting reentrancy, delegatecall drift).                        |
| 8    | **Timing Constraints**            | Fuzz only within certain time windows or block ranges (e.g., before unlock, after epoch).                         |
| 9    | **Storage Collision Constraints** | Target only inputs that mutate specific storage slots or hash collisions.                                         |
| 10   | **Call Context Constraints**      | Force fuzzing through `delegatecall`, `call`, `staticcall`, or `multicall` paths.                                 |
| 11   | **MetaTx/Signature Constraints**  | Restrict inputs to valid signature-encoded MetaTx payloads (EIP-712, SafeTx, etc).                                |
| 12   | **Interface Match Constraints**   | Only fuzz inputs matching known ABIs (e.g., ERC20, ERC721, IBridge).                                              |
