// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OneTimeCryptosystemSuite.sol
/// @notice On-chain analogues of “One-Time Cryptosystem” patterns:
///   Types: Symmetric, Asymmetric, Hybrid  
///   AttackTypes: KeyReuse, ReplayAttack, ImplementationFlaw  
///   DefenseTypes: KeyRotation, ChannelBinding, SafeImplementation, RateLimit  

enum OneTimeCryptosystemType         { Symmetric, Asymmetric, Hybrid }
enum OneTimeCryptosystemAttackType   { KeyReuse, ReplayAttack, ImplementationFlaw }
enum OneTimeCryptosystemDefenseType  { KeyRotation, ChannelBinding, SafeImplementation, RateLimit }

error OTC__NoKey();
error OTC__Reused();
error OTC__InvalidSignature();
error OTC__TooMany();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CRYPTOSYSTEM
//
//    • stores key permanently, reused on each encrypt → KeyReuse
////////////////////////////////////////////////////////////////////////////////
contract OTCSVuln {
    mapping(bytes32 => bytes) public keyStore;  // sessionId → key

    event Encrypted(
        address indexed who,
        bytes32           sessionId,
        bytes             ciphertext,
        OneTimeCryptosystemType   ctype,
        OneTimeCryptosystemAttackType attack
    );

    /// owner or admin loads the key
    function setKey(bytes32 sessionId, bytes calldata key) external {
        keyStore[sessionId] = key;
    }

    /// encrypt by XOR; key remains for reuse
    function encrypt(bytes32 sessionId, bytes calldata plaintext) external {
        bytes memory key = keyStore[sessionId];
        if (key.length == 0) revert OTC__NoKey();
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, sessionId, ct, OneTimeCryptosystemType.Symmetric, OneTimeCryptosystemAttackType.KeyReuse);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates replay of ciphertext and exposure of implementation flaws
////////////////////////////////////////////////////////////////////////////////
contract Attack_OTCS {
    OTCSVuln public target;
    bytes32 public lastSession;
    bytes public lastCT;

    constructor(OTCSVuln _t) {
        target = _t;
    }

    /// capture ciphertext for replay
    function capture(bytes32 sessionId, bytes calldata ciphertext) external {
        lastSession = sessionId;
        lastCT = ciphertext;
    }

    /// replay previously captured ciphertext
    function replay() external {
        // attacker re-sends ciphertext, exploiting lack of freshness
        target.encrypt(lastSession, lastCT);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH KEY ERASURE (KeyRotation)
//
//    • deletes key after use to prevent reuse
////////////////////////////////////////////////////////////////////////////////
contract OTCSafeRotate {
    mapping(bytes32 => bytes) private keyStore;

    event Encrypted(
        address indexed who,
        bytes32           sessionId,
        bytes             ciphertext,
        OneTimeCryptosystemDefenseType defense
    );

    function setKey(bytes32 sessionId, bytes calldata key) external {
        keyStore[sessionId] = key;
    }

    function encrypt(bytes32 sessionId, bytes calldata plaintext) external {
        bytes memory key = keyStore[sessionId];
        if (key.length == 0) revert OTC__NoKey();
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        delete keyStore[sessionId];  // erase key post-use
        emit Encrypted(msg.sender, sessionId, ct, OneTimeCryptosystemDefenseType.KeyRotation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CHANNEL BINDING (SignatureValidation)
//
//    • require off-chain signature over (sessionId||key) to bind channel
////////////////////////////////////////////////////////////////////////////////
contract OTCSafeAuth {
    mapping(bytes32 => bytes) private keyStore;
    address public signer;

    event Encrypted(
        address indexed who,
        bytes32           sessionId,
        bytes             ciphertext,
        OneTimeCryptosystemDefenseType defense
    );

    error OTC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    /// setKey only if signed by trusted signer
    function setKey(
        bytes32 sessionId,
        bytes calldata key,
        bytes calldata sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(sessionId, key));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert OTC__InvalidSignature();
        keyStore[sessionId] = key;
    }

    function encrypt(bytes32 sessionId, bytes calldata plaintext) external {
        bytes memory key = keyStore[sessionId];
        if (key.length == 0) revert OTC__NoKey();
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, sessionId, ct, OneTimeCryptosystemDefenseType.ChannelBinding);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RATE-LIMIT & SAFE IMPLEMENTATION
//
//    • cap encrypt calls per session and guard against edge-cases
////////////////////////////////////////////////////////////////////////////////
contract OTCSafeAdvanced {
    mapping(bytes32 => bytes) private keyStore;
    mapping(bytes32 => uint256) public lastBlock;
    mapping(bytes32 => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 1;

    event Encrypted(
        address indexed who,
        bytes32           sessionId,
        bytes             ciphertext,
        OneTimeCryptosystemDefenseType defense
    );

    error OTC__TooMany();

    function setKey(bytes32 sessionId, bytes calldata key) external {
        keyStore[sessionId] = key;
    }

    function encrypt(bytes32 sessionId, bytes calldata plaintext) external {
        if (block.number != lastBlock[sessionId]) {
            lastBlock[sessionId]    = block.number;
            callsInBlock[sessionId] = 0;
        }
        callsInBlock[sessionId]++;
        if (callsInBlock[sessionId] > MAX_CALLS) revert OTC__TooMany();

        bytes memory key = keyStore[sessionId];
        if (key.length < plaintext.length) revert OTC__NoKey(); // simple safe-implementation guard

        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ key[i];
        }
        emit Encrypted(msg.sender, sessionId, ct, OneTimeCryptosystemDefenseType.RateLimit);
    }
}
