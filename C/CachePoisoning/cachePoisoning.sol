// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CachePoisoningSuite.sol
/// @notice On-chain analogues of “Cache Poisoning” patterns:
///   Types: DNSCache, WebCache, ARPCache, CDNCache  
///   AttackTypes: PoisonEntry, FakeResponse, TamperCache, ReplayAttack  
///   DefenseTypes: SignatureValidation, TTLValidation, CacheIsolation, RateLimit  

enum CachePoisoningType         { DNSCache, WebCache, ARPCache, CDNCache }
enum CachePoisoningAttackType   { PoisonEntry, FakeResponse, TamperCache, ReplayAttack }
enum CachePoisoningDefenseType  { SignatureValidation, TTLValidation, CacheIsolation, RateLimit }

error CP__InvalidSignature();
error CP__EntryExpired();
error CP__NotAuthorized();
error CP__TooManyRequests();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CACHE (no validation, unlimited entries)
///
///    • returns or stores any entry without checks → PoisonEntry
///─────────────────────────────────────────────────────────────────────────────
contract CachePoisonVuln {
    mapping(bytes32 => bytes) public cache;
    event CacheHit(
        address indexed who,
        CachePoisoningType  ctype,
        bytes               data,
        CachePoisoningAttackType attack
    );

    function setEntry(bytes32 key, bytes calldata data) external {
        cache[key] = data;
    }

    function getEntry(bytes32 key, CachePoisoningType ctype) external {
        bytes memory d = cache[key];
        emit CacheHit(msg.sender, ctype, d, CachePoisoningAttackType.PoisonEntry);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (poison & replay)
///
///    • floods fake entries and replays old responses
///─────────────────────────────────────────────────────────────────────────────
contract Attack_CachePoison {
    CachePoisonVuln public target;
    constructor(CachePoisonVuln _t) { target = _t; }

    function poison(bytes32 key, bytes calldata fakeData) external {
        target.setEntry(key, fakeData);
    }

    function replay(bytes32 key, bytes calldata oldData) external {
        target.setEntry(key, oldData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE CACHE WITH SIGNED RESPONSES
///
///    • Defense: SignatureValidation – require valid oracle signature
///─────────────────────────────────────────────────────────────────────────────
contract CachePoisonSafeSigned {
    mapping(bytes32 => bytes) public cache;
    address public signer;
    event CacheHit(
        address indexed who,
        CachePoisoningType  ctype,
        bytes               data,
        CachePoisoningDefenseType defense
    );

    constructor(address _signer) {
        signer = _signer;
    }

    function setEntry(
        bytes32 key,
        bytes calldata data,
        bytes calldata sig
    ) external {
        // verify signature over (key||data)
        bytes32 msgHash = keccak256(abi.encodePacked(key, data));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert CP__InvalidSignature();
        cache[key] = data;
    }

    function getEntry(bytes32 key, CachePoisoningType ctype) external {
        bytes memory d = cache[key];
        emit CacheHit(msg.sender, ctype, d, CachePoisoningDefenseType.SignatureValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE CACHE WITH TTL VALIDATION
///
///    • Defense: TTLValidation – enforce entry expiration
///─────────────────────────────────────────────────────────────────────────────
contract CachePoisonSafeTTL {
    struct Entry { bytes data; uint256 expiry; }
    mapping(bytes32 => Entry) public cache;
    event CacheHit(
        address indexed who,
        CachePoisoningType  ctype,
        bytes               data,
        CachePoisoningDefenseType defense
    );

    function setEntry(bytes32 key, bytes calldata data, uint256 ttl) external {
        // store with expiration
        cache[key] = Entry(data, block.timestamp + ttl);
    }

    function getEntry(bytes32 key, CachePoisoningType ctype) external {
        Entry storage e = cache[key];
        if (block.timestamp > e.expiry) revert CP__EntryExpired();
        emit CacheHit(msg.sender, ctype, e.data, CachePoisoningDefenseType.TTLValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED CACHE WITH RATE-LIMIT & ISOLATION
///
///    • Defense: RateLimit – cap gets per block  
///               CacheIsolation – namespace per user
///─────────────────────────────────────────────────────────────────────────────
contract CachePoisonSafeAdvanced {
    mapping(address => mapping(bytes32 => bytes)) public userCache;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public getsInBlock;
    uint256 public constant MAX_GETS = 5;
    event CacheHit(
        address indexed who,
        CachePoisoningType  ctype,
        bytes               data,
        CachePoisoningDefenseType defense
    );
    error CP__TooManyRequests();

    function setEntry(bytes32 key, bytes calldata data) external {
        userCache[msg.sender][key] = data;
    }

    function getEntry(bytes32 key, CachePoisoningType ctype) external {
        // rate-limit per user
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            getsInBlock[msg.sender] = 0;
        }
        getsInBlock[msg.sender]++;
        if (getsInBlock[msg.sender] > MAX_GETS) revert CP__TooManyRequests();

        bytes memory d = userCache[msg.sender][key];
        emit CacheHit(msg.sender, ctype, d, CachePoisoningDefenseType.RateLimit);
    }
}
