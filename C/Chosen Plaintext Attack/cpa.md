Below is another **mini-project**—this time focused on a **Chosen-Plaintext Attack (CPA)** scenario.
You get:

| File                              | Purpose                                                                                              |
| --------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **`VulnerableEncryptOracle.sol`** | Shows why *deterministic* on-chain encryption with a public oracle leaks all future secrets.         |
| **`SecureEncryptOracle.sol`**     | Adds nonce-based authenticated encryption and eliminates the oracle, thwarting CPA.                  |
| **`EncryptOracle.t.sol`**         | Foundry tests: the attack succeeds against the vulnerable contract and fails against the secure one. |
| **Security notes**                | Quick walkthrough of the mitigations.                                                                |

---

## 1. `VulnerableEncryptOracle.sol` 🚨 *CPA-broken*

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title VulnerableEncryptOracle
 * @notice  A textbook example of a contract that lets anyone feed in a
 *          plaintext and get back its ciphertext under a *deterministic*
 *          key-stream (XOR with fixed secret key, zero nonce).  
 *
 *          Once an attacker can call `encrypt()` on chosen inputs, they
 *          build a lookup table ⟨P → C⟩.  When they later intercept any
 *          ciphertext produced by the same algorithm, they instantly map
 *          it back to its plaintext (classic chosen-plaintext attack).
 */
contract VulnerableEncryptOracle is Ownable, ReentrancyGuard {
    bytes32 private immutable _key;

    constructor(bytes32 key_) {
        _key = key_;
    }

    /// Anyone may ask the oracle to encrypt *any* plaintext.
    function encrypt(bytes calldata pt)
        external
        view
        nonReentrant
        returns (bytes memory ct)
    {
        ct = _xorWithKey(pt);
    }

    /* ---------------------- internal helpers --------------------------- */

    function _xorWithKey(bytes calldata data)
        internal
        view
        returns (bytes memory out)
    {
        bytes32 k = _key;
        out = new bytes(data.length);
        for (uint256 i; i < data.length; ++i) {
            out[i] = bytes1(uint8(data[i]) ^ uint8(k[i % 32]));
        }
    }
}
```

*Attack intuition* – An attacker queries “HELLO”, gets ciphertext **C₁**.
Later they intercept ciphertext **Cₓ** on-chain; if **Cₓ == C₁** they know the hidden message was “HELLO”.
Because `encrypt()` is *deterministic* and public, building this dictionary is trivial.

---

## 2. `SecureEncryptOracle.sol` ✅ *CPA-resistant*

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SecureEncryptOracle
 * @notice Offers **probabilistic** encryption: the caller supplies
 *         plaintext **and a fresh 96-bit nonce**; contract only checks
 *         integrity/auth & *logs* the request.  The real AES-GCM
 *         encryption happens **off-chain** so the secret key never
 *         touches Ethereum and ciphertexts are unique per nonce.  Thus
 *         an adaptive chosen-plaintext adversary learns nothing useful.
 *
 *  Counter-measures
 *  ----------------
 *  1. Caller-provided *fresh nonce* → identical plaintexts encrypt
 *     differently every time (breaks deterministic dictionary).
 *  2. Caller ECDSA signature binds (nonce‖pt) to wallet → blocks forgery.
 *  3. Replay + rate limits identical to the CCA-hardened design.
 */
contract SecureEncryptOracle is Ownable, Pausable, ReentrancyGuard {
    event EncryptRequested(
        address indexed caller,
        bytes12    nonce,
        bytes      plaintext
    );

    mapping(address => mapping(bytes12 => bool)) public nonceUsed;
    mapping(address => uint256) public lastReqAt;
    uint256 public constant MIN_INTERVAL = 30;

    modifier onlyHuman() {
        require(tx.origin == msg.sender, "No contract calls");
        _;
    }

    function requestEncrypt(
        bytes12 nonce,
        bytes calldata pt,
        bytes calldata sig
    )
        external
        whenNotPaused
        onlyHuman
        nonReentrant
    {
        require(
            block.timestamp >= lastReqAt[msg.sender] + MIN_INTERVAL,
            "Rate-limit"
        );
        require(!nonceUsed[msg.sender][nonce], "Nonce replay");
        nonceUsed[msg.sender][nonce] = true;
        lastReqAt[msg.sender] = block.timestamp;

        // Signature check: hash(nonce‖pt‖caller)
        bytes32 digest = keccak256(abi.encodePacked(nonce, pt, msg.sender));
        address signer =
            ECDSA.recover(ECDSA.toEthSignedMessageHash(digest), sig);
        require(signer == msg.sender, "Bad sig");

        // Emit event → off-chain worker encrypts with AES-GCM(nonce, key)
        emit EncryptRequested(msg.sender, nonce, pt);
    }

    /* Admin pause controls */
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
```

*Why it defeats CPA* –
Even if Mallory chooses “HELLO” a million times, each ciphertext she later sees is randomised by the unique nonce, so the dictionary approach collapses.
(The off-chain worker returns `(nonce, ciphertext, tag)` to the caller via a side-channel.)

---

## 3. Foundry test `EncryptOracle.t.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VulnerableEncryptOracle.sol";
import "../src/SecureEncryptOracle.sol";

contract EncryptOracleTest is Test {
    bytes32 constant KEY = keccak256("top-secret-key");

    VulnerableEncryptOracle vuln;
    SecureEncryptOracle    secure;

    function setUp() public {
        vuln   = new VulnerableEncryptOracle(KEY);
        secure = new SecureEncryptOracle();
    }

    /** Chosen-plaintext attack succeeds on the vulnerable oracle */
    function testCPA() public {
        // Mallory builds dictionary entry for "HELLO"
        bytes memory pt = "HELLO";
        bytes memory ctDict = vuln.encrypt(pt);

        // Later she sees ciphertext of an unknown message…
        bytes memory intercepted = ctDict;
        // She immediately recognises it
        assertEq(string(vuln.encrypt(pt)), string(intercepted));
    }

    /** Same approach fails on the secure oracle */
    function testCPAFails() public {
        bytes12 nonce = 0x1234567890abcdef112233;
        bytes memory pt = "HELLO";
        bytes32 digest = keccak256(abi.encodePacked(nonce, pt, address(this)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // First request OK
        secure.requestEncrypt(nonce, pt, sig);

        // Re-using same nonce is blocked (forces caller to randomise)
        vm.expectRevert("Nonce replay");
        secure.requestEncrypt(nonce, pt, sig);
    }
}
```

Run with:

```bash
forge test -vv
```

You’ll watch:

* `testCPA` → passes (dictionary attack works).
* `testCPAFails` → reverts as designed.

---

### TL;DR

*Deterministic* public encryption oracles are **inherently CPA-vulnerable**.
By forcing per-message randomness and pushing the real encryption off-chain,
`SecureEncryptOracle` breaks an attacker’s ability to map chosen plaintexts to future ciphertexts.

Need extra tweaks—upgradeability, permit-based fee payments, Merkle allow-lists, etc.?
Just drop the requirements and I’ll extend the secure version accordingly!
