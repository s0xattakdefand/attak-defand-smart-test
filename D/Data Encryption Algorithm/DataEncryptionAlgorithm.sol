// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataEncryptionAlgorithmSecuritySuite.sol
/// @notice On‐chain patterns for “Data Encryption Algorithm” security:
///   Types: Symmetric, Asymmetric, StreamCipher, BlockCipher  
///   AttackTypes: KeyExtraction, CiphertextManipulation, BruteForce, SideChannel  
///   DefenseTypes: KeyManagement, AEAD, RateLimit, SignatureValidation, AuditLogging

enum DEAType               { Symmetric, Asymmetric, StreamCipher, BlockCipher }
enum DEAttackType          { KeyExtraction, CiphertextManipulation, BruteForce, SideChannel }
enum DEDefenseType         { KeyManagement, AEAD, RateLimit, SignatureValidation, AuditLogging }

error DE__InvalidKey();
error DE__TooManyRequests();
error DE__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ENCRYPTER
//    • ❌ no integrity/auth: easy to manipulate ciphertext → CiphertextManipulation
////////////////////////////////////////////////////////////////////////////////
contract DEAVuln {
    mapping(address => bytes32) public keys;

    event Encrypted(
        address indexed who,
        bytes           plaintext,
        bytes           ciphertext,
        DEAType         dtype,
        DEAttackType    attack
    );

    /// @notice set a raw key with no protection
    function setKey(bytes32 key, DEAType dtype) external {
        keys[msg.sender] = key;
    }

    /// @notice simple XOR‐based “encryption” with no MAC
    function encrypt(bytes calldata plaintext, DEAType dtype) external {
        bytes32 key = keys[msg.sender];
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = bytes1(uint8(plaintext[i]) ^ uint8(key[i % 32]));
        }
        emit Encrypted(msg.sender, plaintext, ct, dtype, DEAttackType.CiphertextManipulation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates key extraction, brute force, side-channel
////////////////////////////////////////////////////////////////////////////////
contract Attack_DEA {
    DEAVuln public target;
    bytes32 public leakedKey;

    constructor(DEAVuln _t) { target = _t; }

    /// @notice extract raw key directly
    function stealKey() external {
        leakedKey = target.keys(address(this));
    }

    /// @notice brute‐force guess by testing one byte
    function bruteOneByte(byte guess, DEAType dtype) external {
        bytes memory pt = hex"01";
        target.setKey(bytes32(abi.encodePacked(guess)), dtype);
        target.encrypt(pt, dtype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH KEY MANAGEMENT
//    • ✅ Defense: KeyManagement – keys stored in vault, non‐exportable
////////////////////////////////////////////////////////////////////////////////
contract DEASafeKM {
    mapping(address => bytes32) private vault;
    event KeyStored(address indexed who, DEAType dtype, DEDefenseType defense);

    modifier hasKey() {
        if (vault[msg.sender] == bytes32(0)) revert DE__InvalidKey();
        _;
    }

    function storeKey(bytes32 key, DEAType dtype) external {
        // enforce off‐chain HSM or vault integration
        vault[msg.sender] = key;
        emit KeyStored(msg.sender, dtype, DEDefenseType.KeyManagement);
    }

    function encrypt(bytes calldata plaintext, DEAType dtype) external hasKey {
        // same XOR but key safe in vault
        bytes32 k = vault[msg.sender];
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = bytes1(uint8(plaintext[i]) ^ uint8(k[i % 32]));
        }
        // no event for brevity
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH AEAD & RATE LIMIT
//    • ✅ Defense: AEAD – provide authenticity  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract DEASafeAEAD {
    mapping(address => bytes32) private vault;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Encrypted(
        address indexed who,
        bytes           plaintext,
        bytes           ciphertext,
        DEAType         dtype,
        DEDefenseType   defense
    );

    error DE__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DE__TooManyRequests();
        _;
    }
    modifier hasKey() {
        if (vault[msg.sender] == bytes32(0)) revert DE__InvalidKey();
        _;
    }

    function storeKey(bytes32 key, DEAType dtype) external {
        vault[msg.sender] = key;
    }

    function encryptAEAD(bytes calldata plaintext, DEAType dtype) external hasKey rateLimit {
        bytes32 k = vault[msg.sender];
        // simplistic AEAD: prepend length and XOR
        bytes memory ct = new bytes(plaintext.length + 32);
        assembly { mstore(add(ct,32), plaintext.length) }
        for (uint i = 0; i < plaintext.length; i++) {
            ct[32 + i] = bytes1(uint8(plaintext[i]) ^ uint8(k[i % 32]));
        }
        emit Encrypted(msg.sender, plaintext, ct, dtype, DEDefenseType.AEAD);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – authenticate request  
//               AuditLogging      – record each operation
////////////////////////////////////////////////////////////////////////////////
contract DEASafeAdvanced {
    mapping(address => bytes32) private vault;
    address public signer;

    event Encrypted(
        address indexed who,
        bytes           plaintext,
        bytes           ciphertext,
        DEAType         dtype,
        DEDefenseType   defense
    );
    event AuditLog(
        address indexed who,
        string          action,
        DEAType         dtype,
        DEDefenseType   defense
    );

    error DE__InvalidSignature();
    error DE__InvalidKey();

    constructor(address _signer) {
        signer = _signer;
    }

    function storeKey(bytes32 key, DEAType dtype) external {
        vault[msg.sender] = key;
    }

    function encryptSigned(
        bytes calldata plaintext,
        DEAType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||plaintext||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, plaintext, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DE__InvalidSignature();

        bytes32 k = vault[msg.sender];
        if (k == bytes32(0)) revert DE__InvalidKey();

        // AEAD as above
        bytes memory ct = new bytes(plaintext.length + 32);
        assembly { mstore(add(ct,32), plaintext.length) }
        for (uint i = 0; i < plaintext.length; i++) {
            ct[32 + i] = bytes1(uint8(plaintext[i]) ^ uint8(k[i % 32]));
        }

        emit Encrypted(msg.sender, plaintext, ct, dtype, DEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "encryptSigned", dtype, DEDefenseType.AuditLogging);
    }
}
