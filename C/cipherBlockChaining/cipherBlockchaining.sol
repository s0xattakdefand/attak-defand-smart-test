// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CBCSuite.sol
/// @notice On‐chain analogues of **Cipher Block Chaining** (CBC) encryption modes:
///   Types: Standard, Padded, Authenticated, CustomIV  
///   AttackTypes: PaddingOracle, IVManipulation, BitFlipping, Replay  
///   DefenseTypes: RandomIV, PaddingValidation, AuthenticatedEncrypt, RateLimit, AccessControl

enum CBCType             { Standard, Padded, Authenticated, CustomIV }
enum CBCAttackType       { PaddingOracle, IVManipulation, BitFlipping, Replay }
enum CBCDefenseType      { RandomIV, PaddingValidation, AuthenticatedEncrypt, RateLimit, AccessControl }

error CBC__NotOwner();
error CBC__InvalidPadding();
error CBC__TooManyRequests();
error CBC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CBC ENCRYPTOR
//    • ❌ static IV + no padding check → PaddingOracle, IVManipulation
////////////////////////////////////////////////////////////////////////////////
contract CBCVuln {
    bytes public key;
    bytes public iv;

    event Encrypted(
        address indexed who,
        bytes             plaintext,
        bytes             ciphertext,
        CBCType           ctype,
        CBCAttackType     attack
    );

    function setKeyAndIV(bytes calldata k, bytes calldata _iv, CBCType ctype) external {
        key = k;
        iv  = _iv;
    }

    function encrypt(bytes calldata plaintext, CBCType ctype) external {
        // naive CBC stub: XOR with static IV only once
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ iv[i % iv.length] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CBCAttackType.IVManipulation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates padding oracle, IV tampering, bit‐flipping, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_CBC {
    CBCVuln public target;
    bytes    public lastPlain;
    bytes    public lastCipher;
    CBCType  public lastType;

    constructor(CBCVuln _t) { target = _t; }

    function capture(bytes calldata pt, bytes calldata ct, CBCType ctype) external {
        lastPlain  = pt;
        lastCipher = ct;
        lastType   = ctype;
    }

    function paddingOracle(bytes calldata ct) external {
        // attacker probes decryption errors
        target.encrypt(lastPlain, lastType);
    }

    function flipIV(bytes calldata ivTamper) external {
        // simulate IVManipulation by resetting IV then re-encrypt
        target.setKeyAndIV(target.key(), ivTamper, lastType);
        target.encrypt(lastPlain, lastType);
    }

    function replay() external {
        target.encrypt(lastPlain, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may set key/IV or encrypt
////////////////////////////////////////////////////////////////////////////////
contract CBCSafeAccess {
    bytes public key;
    bytes public iv;
    address public owner;

    event Encrypted(
        address indexed who,
        bytes             plaintext,
        bytes             ciphertext,
        CBCType           ctype,
        CBCDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert CBC__NotOwner();
        _;
    }

    function setKeyAndIV(bytes calldata k, bytes calldata _iv, CBCType) external onlyOwner {
        key = k;
        iv  = _iv;
    }

    function encrypt(bytes calldata plaintext, CBCType ctype) external onlyOwner {
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ iv[i % iv.length] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, ct, ctype, CBCDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RANDOM IV & PADDING VALIDATION + RATE LIMIT
//    • ✅ Defense: RandomIV – fresh IV per encrypt  
//               PaddingValidation – check padding stub  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract CBCSafeValidate {
    bytes public key;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event Encrypted(
        address indexed who,
        bytes             plaintext,
        bytes             iv,
        bytes             ciphertext,
        CBCType           ctype,
        CBCDefenseType    defense
    );

    error CBC__InvalidPadding();
    error CBC__TooManyRequests();

    function setKey(bytes calldata k) external {
        key = k;
    }

    function _checkPadding(bytes memory pt) internal pure {
        // stub: require last byte ≤ block size
        uint8 pad = uint8(pt[pt.length - 1]);
        if (pad == 0 || pad > pt.length) revert CBC__InvalidPadding();
    }

    function encrypt(bytes calldata plaintext, CBCType ctype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CBC__TooManyRequests();

        // padding validation
        bytes memory pt = bytes(plaintext);
        _checkPadding(pt);

        // fresh IV stub: derive from blockhash
        bytes memory freshIV = abi.encodePacked(blockhash(block.number - 1));
        bytes memory ct = new bytes(pt.length);
        for (uint i = 0; i < pt.length; i++) {
            ct[i] = (i == 0 ? freshIV[0] : ct[i - 1]) ^ pt[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, plaintext, freshIV, ct, ctype, CBCDefenseType.PaddingValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH AUTHENTICATED ENCRYPTION & SIGNATURE VALIDATION
//    • ✅ Defense: AuthenticatedEncrypt – stub AEAD  
//               SignatureValidation – require admin signature
////////////////////////////////////////////////////////////////////////////////
contract CBCSafeAdvanced {
    bytes public key;
    address public signer;

    event Encrypted(
        address indexed who,
        bytes             plaintext,
        bytes             iv,
        bytes             ciphertext,
        CBCType           ctype,
        CBCDefenseType    defense
    );

    error CBC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setKey(
        bytes calldata k,
        bytes calldata sig
    ) external {
        // verify signature over key
        bytes32 h = keccak256(abi.encodePacked(k));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CBC__InvalidSignature();
        key = k;
    }

    function encrypt(bytes calldata plaintext, CBCType ctype) external {
        // stub AEAD: prepend IV and append “auth tag”
        bytes memory iv = abi.encodePacked(keccak256(plaintext));
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = (i == 0 ? iv[0] : ct[i - 1]) ^ plaintext[i] ^ key[i % key.length];
        }
        bytes memory authTag = abi.encodePacked(keccak256(abi.encodePacked(ct, key)));
        bytes memory full = abi.encodePacked(iv, ct, authTag);
        emit Encrypted(msg.sender, plaintext, iv, full, ctype, CBCDefenseType.AuthenticatedEncrypt);
    }
}
