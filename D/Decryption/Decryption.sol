// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DecryptionSuite.sol
/// @notice On‑chain analogues of “Decryption” patterns:
///   Types: Symmetric, Asymmetric, Stream, Block  
///   AttackTypes: KeyRecovery, PaddingOracle, ChosenCiphertext, ReplayAttack  
///   DefenseTypes: SecureKeyStorage, PaddingCheck, AuthenticatedDecryption, NonceProtect  

enum DecryptionType           { Symmetric, Asymmetric, Stream, Block }
enum DecryptionAttackType     { KeyRecovery, PaddingOracle, ChosenCiphertext, ReplayAttack }
enum DecryptionDefenseType    { SecureKeyStorage, PaddingCheck, AuthenticatedDecryption, NonceProtect }

error DEC__BadPadding();
error DEC__NotAuthorized();
error DEC__ReplayDetected();
error DEC__NoKey();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DECRYPTION (no key protection, no padding or integrity checks)
///─────────────────────────────────────────────────────────────────────────────
contract DecryptionVuln {
    event Decrypted(
        address indexed who,
        DecryptionType   dtype,
        bytes            plaintext,
        DecryptionAttackType attack
    );

    /// ❌ naive: returns ciphertext as “plaintext” and accepts any key
    function decrypt(
        DecryptionType dtype,
        bytes calldata ciphertext,
        bytes calldata key
    ) external returns (bytes memory) {
        bytes memory pt = ciphertext;
        emit Decrypted(msg.sender, dtype, pt, DecryptionAttackType.KeyRecovery);
        return pt;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (padding oracle & replay)
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Decryption {
    DecryptionVuln public target;
    constructor(DecryptionVuln _t) { target = _t; }

    /// Attempt a padding oracle by observing revert vs success
    function paddingOracle(
        DecryptionType dtype,
        bytes calldata ct,
        bytes calldata wrongKey
    ) external returns (bool) {
        try target.decrypt(dtype, ct, wrongKey) returns (bytes memory) {
            return true; // oracle indicates “valid padding”
        } catch {
            return false; // indicates padding error
        }
    }

    /// Replay attack: simply resend ciphertext
    function replay(
        DecryptionType dtype,
        bytes calldata ct,
        bytes calldata key
    ) external returns (bytes memory) {
        return target.decrypt(dtype, ct, key);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DECRYPTION WITH SECURE KEY STORAGE & PADDING CHECK
///─────────────────────────────────────────────────────────────────────────────
contract DecryptionSafeBasic {
    address public owner;
    mapping(DecryptionType => bytes) private _keys;

    event Decrypted(
        address indexed who,
        DecryptionType   dtype,
        bytes            plaintext,
        DecryptionDefenseType defense
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "DecryptionSafeBasic: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// ✅ owner securely sets per‑type key
    function setKey(DecryptionType dtype, bytes calldata key) external onlyOwner {
        _keys[dtype] = key;
    }

    /// ✅ padding‑aware decryption: simple PKCS#7 stub
    function decrypt(
        DecryptionType dtype,
        bytes calldata ciphertext
    ) external returns (bytes memory) {
        bytes memory key = _keys[dtype];
        if (key.length == 0) revert DEC__NoKey();

        // stub decryption: plaintext = ciphertext
        bytes memory pt = ciphertext;

        // padding check: last byte indicates pad length
        uint8 pad = uint8(pt[pt.length - 1]);
        if (pad == 0 || pad > pt.length) revert DEC__BadPadding();
        for (uint i = pt.length - pad; i < pt.length; i++) {
            if (pt[i] != bytes1(pad)) revert DEC__BadPadding();
        }

        // strip padding
        bytes memory out = new bytes(pt.length - pad);
        for (uint i = 0; i < out.length; i++) {
            out[i] = pt[i];
        }

        emit Decrypted(msg.sender, dtype, out, DecryptionDefenseType.PaddingCheck);
        return out;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED DECRYPTION WITH AUTHENTICATED DECRYPTION & NONCE PROTECTION
///─────────────────────────────────────────────────────────────────────────────
contract DecryptionSafeAdvanced {
    address public owner;
    mapping(DecryptionType => bytes) private _keys;
    mapping(bytes32 => bool)   private _usedNonce;

    event Decrypted(
        address indexed who,
        DecryptionType   dtype,
        bytes            plaintext,
        DecryptionDefenseType defense
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "DecryptionSafeAdvanced: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// ✅ owner sets per‑type key
    function setKey(DecryptionType dtype, bytes calldata key) external onlyOwner {
        _keys[dtype] = key;
    }

    /// ✅ authenticated decryption with nonce to prevent replay
    /// ciphertext format: abi.encodePacked(nonce, ct, mac)
    function decrypt(
        DecryptionType dtype,
        bytes calldata payload
    ) external returns (bytes memory) {
        bytes memory key = _keys[dtype];
        if (key.length == 0) revert DEC__NoKey();

        // parse nonce (32 bytes), ct, and mac (32 bytes)
        require(payload.length > 64, "payload too short");
        bytes32 nonce;
        bytes32 mac;
        bytes memory ct = new bytes(payload.length - 64);
        assembly {
            nonce := calldataload(payload.offset)
            // copy ct
            let src := add(payload.offset, 32)
            let dst := ct
            let len := sub(mload(payload), 64)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), calldataload(add(src, i)))
            }
            mac := calldataload(add(payload.offset, add(32, len)))
        }

        // replay protection
        if (_usedNonce[nonce]) revert DEC__ReplayDetected();
        _usedNonce[nonce] = true;

        // stub MAC check: keccak256(ct || key || nonce)
        bytes32 expected = keccak256(abi.encodePacked(ct, key, nonce));
        if (expected != mac) revert DEC__NotAuthorized();

        // stub decryption: plaintext = ct
        bytes memory pt = ct;

        emit Decrypted(msg.sender, dtype, pt, DecryptionDefenseType.AuthenticatedDecryption);
        return pt;
    }
}
