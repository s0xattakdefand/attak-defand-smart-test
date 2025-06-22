// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SymmetricKeySuite.sol
/// @notice Four on‑chain “Symmetric Key” patterns illustrating common
///         vulnerabilities and hardened defenses.

error SK__Unauthorized();
error SK__Replayed();
error SK__BadNonce();
error SK__RotationNotAllowed();

//------------------------------------------------------------------------------
// ECDSA RECOVERY LIBRARY (for Safe modules)
//------------------------------------------------------------------------------
library ECDSALib {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "ECDSA: bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid signature");
    }
}

//------------------------------------------------------------------------------
// 1) HARDCODED KEY VULNERABILITY
//    – Vulnerable: secret key baked into bytecode
//    – Attack: attacker reads it via public getter
//    – Defense: no on‑chain key; require off‑chain signature to derive a session key
//------------------------------------------------------------------------------
contract SymKeyHardcodedVuln {
    bytes32 public constant SYM_KEY =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    function getKey() external pure returns (bytes32) {
        return SYM_KEY;
    }
}

contract Attack_SymKeyHardcoded {
    SymKeyHardcodedVuln public target;
    constructor(SymKeyHardcodedVuln _t) { target = _t; }
    function steal() external view returns (bytes32) {
        return target.getKey();
    }
}

contract SymKeyHardcodedSafe {
    using ECDSALib for bytes32;
    address public immutable manager;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("DeriveKey(address who,uint256 nonce,uint256 expiry)");

    mapping(uint256 => bool) public usedNonce;

    constructor(address _mgr) {
        manager = _mgr;
        DOMAIN  = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("SymKeyHardcodedSafe"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice Derive a per‑call session key only if signed by `manager`
    function deriveKey(
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external returns (bytes32) {
        require(block.timestamp <= expiry, "SK: expired");
        require(!usedNonce[nonce], "SK: replay");

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, msg.sender, nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != manager) revert SK__Unauthorized();

        usedNonce[nonce] = true;
        // derive session key off‑chain secret + parameters
        return keccak256(abi.encodePacked(msg.sender, nonce, expiry));
    }
}

//------------------------------------------------------------------------------
// 2) PUBLIC STORAGE OF KEY
//    – Vulnerable: symmetric key stored in public mapping
//    – Attack: anyone reads mapping via auto‑getter
//    – Defense: key storage is private and validated via signature
//------------------------------------------------------------------------------
contract SymKeyStorageVuln {
    mapping(address => bytes32) public keyStore;
    function setKey(bytes32 k) external {
        keyStore[msg.sender] = k;
    }
}

contract Attack_SymKeyStorage {
    SymKeyStorageVuln public target;
    constructor(SymKeyStorageVuln _t) { target = _t; }
    function sniff(address user) external view returns (bytes32) {
        return target.keyStore(user);
    }
}

contract SymKeyStorageSafe {
    using ECDSALib for bytes32;
    mapping(address => bytes32) private _keyStore;
    mapping(bytes32 => bool) public usedSig;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("StoreKey(address user,bytes32 key,uint256 nonce)");

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("SymKeyStorageSafe"),
            block.chainid,
            address(this)
        ));
    }

    function setKey(
        bytes32 k,
        uint256 nonce,
        bytes calldata sig
    ) external {
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, msg.sender, k, nonce));
        bytes32 digest    = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (usedSig[digest]) revert SK__Replayed();
        address signer = digest.recover(sig);
        require(signer == msg.sender, "SK: bad sig");

        usedSig[digest]      = true;
        _keyStore[msg.sender] = k;
    }

    function verifyKey(bytes32 k) external view returns (bool) {
        return _keyStore[msg.sender] == k;
    }
}

//------------------------------------------------------------------------------
// 3) KEY REUSE IN SYMMETRIC CIPHER
//    – Vulnerable: same key used to XOR‑encrypt multiple messages → keystream reuse
//    – Attack: E1 ^ E2 = P1 ^ P2 leaks plaintext XOR
//    – Defense: derive per‑message subkey with nonce
//------------------------------------------------------------------------------
library XORCipher {
    function encrypt(bytes memory key, bytes memory data) internal pure returns (bytes memory) {
        bytes memory out = new bytes(data.length);
        for (uint i = 0; i < data.length; i++) {
            out[i] = data[i] ^ key[i % key.length];
        }
        return out;
    }
}

/// Vulnerable: reuses a fixed key
contract SymKeyReuseVuln {
    using XORCipher for bytes;
    bytes public key;
    mapping(uint256 => bytes) public ciphertexts;

    constructor(bytes memory _key) { key = _key; }

    function encryptAndStore(uint256 id, bytes calldata plaintext) external {
        ciphertexts[id] = plaintext.encrypt(key);
    }
}

/// Attack: given two ciphertexts E1,E2 → compute E1^E2 = P1^P2
contract Attack_SymKeyReuse {
    SymKeyReuseVuln public target;
    constructor(SymKeyReuseVuln _t) { target = _t; }

    function leakXor(uint256 id1, uint256 id2) external view returns (bytes memory) {
        bytes memory c1 = target.ciphertexts(id1);
        bytes memory c2 = target.ciphertexts(id2);
        require(c1.length == c2.length, "len"); 
        bytes memory out = new bytes(c1.length);
        for (uint i = 0; i < c1.length; i++) {
            out[i] = c1[i] ^ c2[i];
        }
        return out; // equals P1 ^ P2
    }
}

/// Safe: derive subkey per message using a nonce
contract SymKeyReuseSafe {
    using XORCipher for bytes;
    bytes public masterKey;

    mapping(uint256 => bytes) public ciphertexts;
    mapping(uint256 => bool) public usedNonce;

    constructor(bytes memory _masterKey) { masterKey = _masterKey; }

    function encryptAndStore(
        uint256 id,
        bytes calldata plaintext,
        uint256 nonce
    ) external {
        require(!usedNonce[nonce], "SK: nonce used");
        usedNonce[nonce] = true;

        // derive per‑message key
        bytes32 subKeyHash = keccak256(abi.encodePacked(masterKey, nonce));
        bytes memory subKey = abi.encodePacked(subKeyHash);
        ciphertexts[id] = plaintext.encrypt(subKey);
    }
}

//------------------------------------------------------------------------------
// 4) KEY ROTATION
//    – Vulnerable: key never rotates → compromise permanent
//    – Attack: once key leaked, all past/future data compromised
//    – Defense: owner‑controlled rotation with versioning
//------------------------------------------------------------------------------
contract SymKeyRotationVuln {
    bytes32 public key;
    constructor(bytes32 _key) { key = _key; }
}

contract Attack_SymKeyRotation {
    SymKeyRotationVuln public target;
    constructor(SymKeyRotationVuln _t) { target = _t; }
    function steal() external view returns (bytes32) {
        return target.key();
    }
}

contract SymKeyRotationSafe {
    address public owner;
    mapping(uint256 => bytes32) public versionedKey;
    uint256 public currentVersion;

    error SK__RotationNotAllowed();

    event KeyRotated(uint256 version, bytes32 newKey);

    constructor(bytes32 initialKey) {
        owner = msg.sender;
        versionedKey[0] = initialKey;
        currentVersion = 0;
    }

    function rotateKey(bytes32 newKey) external {
        if (msg.sender != owner) revert SK__RotationNotAllowed();
        currentVersion += 1;
        versionedKey[currentVersion] = newKey;
        emit KeyRotated(currentVersion, newKey);
    }

    function getKey(uint256 version) external view returns (bytes32) {
        require(version <= currentVersion, "SK: bad version");
        return versionedKey[version];
    }
}
