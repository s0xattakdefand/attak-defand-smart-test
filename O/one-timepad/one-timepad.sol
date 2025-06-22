// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OneTimePadSuite.sol
/// @notice On-chain analogues of “One-Time Pad” encryption patterns:
///   Types: PreShared, Dynamic, Hybrid  
///   AttackTypes: KeyReuse, PadExposure, ReplayAttack  
///   DefenseTypes: KeyErasure, RandomnessSource, RateLimit, AuthChallenge  

enum OneTimePadType           { PreShared, Dynamic, Hybrid }
enum OneTimePadAttackType     { KeyReuse, PadExposure, ReplayAttack }
enum OneTimePadDefenseType    { KeyErasure, RandomnessSource, RateLimit, AuthChallenge }

error OTP__NoPad();
error OTP__Reused();
error OTP__TooMany();
error OTP__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OTP SERVICE
//    • no erasure or nonce: pad reused on every encrypt → KeyReuse
////////////////////////////////////////////////////////////////////////////////
contract OTPVuln {
    mapping(bytes32 => bytes) public pad;    // msgId → pad
    event Encrypted(
        address indexed who,
        bytes32           msgId,
        bytes             ciphertext,
        OneTimePadType    ptype,
        OneTimePadAttackType attack
    );

    /// owner sets pre-shared pad
    function setPad(bytes32 msgId, bytes calldata key) external {
        pad[msgId] = key;
    }

    /// encrypt by simple XOR, pad stays for reuse
    function encrypt(bytes32 msgId, bytes calldata plaintext) external {
        bytes memory key = pad[msgId];
        if (key.length == 0) revert OTP__NoPad();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, msgId, ct, OneTimePadType.PreShared, OneTimePadAttackType.KeyReuse);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates pad exposure and replay decryption
////////////////////////////////////////////////////////////////////////////////
contract Attack_OneTimePad {
    OTPVuln public target;
    event Decrypted(
        address indexed who,
        bytes32           msgId,
        bytes             plaintext,
        OneTimePadAttackType attack
    );

    constructor(OTPVuln _t) {
        target = _t;
    }

    /// capture pad and ciphertext, then decrypt
    function decrypt(bytes32 msgId, bytes calldata ciphertext) external {
        bytes memory key = target.pad(msgId);
        require(key.length > 0, "no pad");
        uint256 n = ciphertext.length;
        bytes memory pt = new bytes(n);
        for (uint i = 0; i < n; i++) {
            pt[i] = ciphertext[i] ^ key[i % key.length];
        }
        emit Decrypted(msg.sender, msgId, pt, OneTimePadAttackType.PadExposure);
    }

    /// replay encryption call
    function replayEncrypt(bytes32 msgId, bytes calldata plaintext) external {
        target.encrypt(msgId, plaintext);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE OTP WITH KEY ERASURE
//    • Defense: KeyErasure – delete pad after use
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeErase {
    mapping(bytes32 => bytes) private pad;
    event Encrypted(
        address indexed who,
        bytes32           msgId,
        bytes             ciphertext,
        OneTimePadDefenseType defense
    );
    error OTP__NoPad();

    function setPad(bytes32 msgId, bytes calldata key) external {
        pad[msgId] = key;
    }

    function encrypt(bytes32 msgId, bytes calldata plaintext) external {
        bytes memory key = pad[msgId];
        if (key.length == 0) revert OTP__NoPad();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        delete pad[msgId];  // erase key to prevent reuse
        emit Encrypted(msg.sender, msgId, ct, OneTimePadDefenseType.KeyErasure);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE OTP WITH DYNAMIC PAD & AUTH CHALLENGE
//    • Defense: AuthChallenge – require owner signature for pad
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeRand {
    mapping(bytes32 => bytes) private pad;
    address public oracle;
    event Encrypted(
        address indexed who,
        bytes32           msgId,
        bytes             ciphertext,
        OneTimePadDefenseType defense
    );
    error OTP__InvalidSignature();
    error OTP__NoPad();

    constructor(address _oracle) {
        oracle = _oracle;
    }

    /// set pad only with oracle signature over (msgId||key)
    function setPad(
        bytes32 msgId,
        bytes calldata key,
        bytes calldata sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(msgId, key));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != oracle) revert OTP__InvalidSignature();
        pad[msgId] = key;
    }

    function encrypt(bytes32 msgId, bytes calldata plaintext) external {
        bytes memory key = pad[msgId];
        if (key.length == 0) revert OTP__NoPad();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, msgId, ct, OneTimePadDefenseType.AuthChallenge);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE OTP ADVANCED WITH RATE-LIMITING
//    • Defense: RateLimit – cap encrypt calls per msgId
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeRateLimit {
    mapping(bytes32 => bytes) private pad;
    mapping(bytes32 => uint256) public lastBlock;
    mapping(bytes32 => uint256) public usesInBlock;
    uint256 public constant MAX_USES = 1;

    event Encrypted(
        address indexed who,
        bytes32           msgId,
        bytes             ciphertext,
        OneTimePadDefenseType defense
    );
    error OTP__NoPad();
    error OTP__TooMany();

    function setPad(bytes32 msgId, bytes calldata key) external {
        pad[msgId] = key;
    }

    function encrypt(bytes32 msgId, bytes calldata plaintext) external {
        if (block.number != lastBlock[msgId]) {
            lastBlock[msgId]    = block.number;
            usesInBlock[msgId] = 0;
        }
        usesInBlock[msgId]++;
        if (usesInBlock[msgId] > MAX_USES) revert OTP__TooMany();

        bytes memory key = pad[msgId];
        if (key.length == 0) revert OTP__NoPad();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, msgId, ct, OneTimePadDefenseType.RateLimit);
    }
}
