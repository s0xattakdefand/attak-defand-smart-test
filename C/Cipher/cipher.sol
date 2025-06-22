// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CipherSuite.sol
/// @notice On‐chain analogues of “Cipher” encryption/decryption patterns:
///   Types: Symmetric, Asymmetric, Stream, Block  
///   AttackTypes: KeyRecovery, BruteForce, SideChannel, Replay  
///   DefenseTypes: KeyRotation, StrongMode, PaddingValidation, RateLimit, AccessControl

enum CipherType            { Symmetric, Asymmetric, Stream, Block }
enum CipherAttackType      { KeyRecovery, BruteForce, SideChannel, Replay }
enum CipherDefenseType     { KeyRotation, StrongMode, PaddingValidation, RateLimit }

error CPH__NotOwner();
error CPH__InvalidPadding();
error CPH__TooManyRequests();
error CPH__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CIPHER
//    • ❌ static key & no padding checks → KeyRecovery, SideChannel
////////////////////////////////////////////////////////////////////////////////
contract CipherVuln {
    bytes public key; // static key

    event Encrypted(
        address indexed who,
        bytes               plaintext,
        bytes               ciphertext,
        CipherType          ctype,
        CipherAttackType    attack
    );

    function setKey(bytes calldata k, CipherType ctype) external {
        key = k;
    }

    function encrypt(bytes calldata plaintext, CipherType ctype) external {
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            // naive XOR
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CipherAttackType.SideChannel);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates brute‐force & key recovery
////////////////////////////////////////////////////////////////////////////////
contract Attack_Cipher {
    CipherVuln public target;
    bytes public knownPlain;
    bytes public observedCt;
    CipherType public lastType;

    constructor(CipherVuln _t) { target = _t; }

    function capture(bytes calldata plaintext, bytes calldata ciphertext, CipherType ctype) external {
        knownPlain = plaintext;
        observedCt  = ciphertext;
        lastType    = ctype;
    }

    function bruteForceRecover(uint256 maxKeyLen) external {
        // stub: attacker tries small keys
        target.encrypt(knownPlain, lastType);
        // in reality would iterate key guesses offline
    }

    function replay(bytes calldata plaintext) external {
        target.encrypt(plaintext, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH KEY ROTATION & ACCESS CONTROL
//    • ✅ Defense: KeyRotation – only owner may update key  
//               AccessControl – owner‐only encrypt
////////////////////////////////////////////////////////////////////////////////
contract CipherSafeRotate {
    bytes public key;
    address public owner;
    uint256 public lastRotation;
    uint256 public rotationInterval;

    event KeyRotated(
        address indexed who,
        CipherDefenseType defense
    );
    event Encrypted(
        address indexed who,
        bytes               plaintext,
        bytes               ciphertext,
        CipherType          ctype,
        CipherDefenseType   defense
    );

    error CPH__NotOwner();
    error CPH__TooFrequent();

    constructor(uint256 interval) {
        owner = msg.sender;
        rotationInterval = interval;
        lastRotation = block.timestamp;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert CPH__NotOwner();
        _;
    }

    function rotateKey(bytes calldata k) external onlyOwner {
        if (block.timestamp < lastRotation + rotationInterval) revert CPH__TooManyRequests();
        key = k;
        lastRotation = block.timestamp;
        emit KeyRotated(msg.sender, CipherDefenseType.KeyRotation);
    }

    function encrypt(bytes calldata plaintext, CipherType ctype) external onlyOwner {
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CipherDefenseType.KeyRotation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH PADDING VALIDATION & RATE LIMIT
//    • ✅ Defense: PaddingValidation – simple PKCS#7‐style check  
//               RateLimit           – cap per block
////////////////////////////////////////////////////////////////////////////////
contract CipherSafeValidate {
    bytes public key;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Encrypted(
        address indexed who,
        bytes               plaintext,
        bytes               ciphertext,
        CipherType          ctype,
        CipherDefenseType   defense
    );

    error CPH__InvalidPadding();
    error CPH__TooManyRequests();

    function setKey(bytes calldata k) external {
        key = k;
    }

    function _checkPadding(bytes memory pt) internal pure {
        // stub: require length ≥ 1 and last byte ≤ block size
        uint8 pad = uint8(pt[pt.length - 1]);
        if (pad == 0 || pad > pt.length) revert CPH__InvalidPadding();
    }

    function encrypt(bytes calldata plaintext, CipherType ctype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CPH__TooManyRequests();

        bytes memory pt = bytes(plaintext);
        _checkPadding(pt);

        bytes memory ct = new bytes(pt.length);
        for (uint i = 0; i < pt.length; i++) {
            ct[i] = pt[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CipherDefenseType.PaddingValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & STRONG MODE
//    • ✅ Defense: SignatureValidation – require admin signature  
//               StrongMode         – enforce block‐cipher chaining stub
////////////////////////////////////////////////////////////////////////////////
contract CipherSafeAdvanced {
    bytes public key;
    address public signer;

    event KeyUpdated(
        address indexed who,
        CipherDefenseType defense
    );
    event Encrypted(
        address indexed who,
        bytes               plaintext,
        bytes               ciphertext,
        CipherType          ctype,
        CipherDefenseType   defense
    );

    error CPH__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function updateKey(bytes calldata k, bytes calldata sig) external {
        bytes32 h = keccak256(abi.encodePacked(k));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CPH__InvalidSignature();
        key = k;
        emit KeyUpdated(msg.sender, CipherDefenseType.StrongMode);
    }

    function encrypt(bytes calldata plaintext, CipherType ctype) external {
        // stub strong mode: CBC‐like chaining
        bytes memory ct = new bytes(plaintext.length);
        bytes1 iv = bytes1(uint8(uint256(keccak256(plaintext)) & 0xFF));
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = (plaintext[i] ^ iv) ^ key[i % key.length];
            iv = ct[i];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CipherDefenseType.StrongMode);
    }
}
