// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ValidatingCacheSuite.sol
/// @notice On-chain analogues of “Validating Cache” patterns:
///   Types: Freshness, Consistency, Expiration, Validation  
///   AttackTypes: StaleCache, PoisonEntry, Replay  
///   DefenseTypes: TTLValidation, SignatureValidation, CachePurge, RateLimit  

enum ValidatingCacheType          { Freshness, Consistency, Expiration, Validation }
enum ValidatingCacheAttackType    { StaleCache, PoisonEntry, Replay }
enum ValidatingCacheDefenseType   { TTLValidation, SignatureValidation, CachePurge, RateLimit }

error VC__EntryExpired();
error VC__InvalidSignature();
error VC__TooManyRequests();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CACHE (no validation, returns stale or poisoned data)
///    • Attack: StaleCache, PoisonEntry
///─────────────────────────────────────────────────────────────────────────────
contract ValidatingCacheVuln {
    mapping(bytes32 => bytes) public cacheData;
    mapping(bytes32 => uint256) public cacheTime;

    event CacheRetrieved(
        address indexed who,
        bytes32           key,
        bytes             data,
        ValidatingCacheAttackType attack
    );

    function setCache(bytes32 key, bytes calldata data) external {
        cacheData[key] = data;
        cacheTime[key] = block.timestamp;
    }

    function getCache(bytes32 key) external {
        bytes memory d = cacheData[key];
        emit CacheRetrieved(msg.sender, key, d, ValidatingCacheAttackType.StaleCache);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (replay old entries, inject poisoned data)
///    • Attack: Replay, PoisonEntry
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ValidatingCache {
    ValidatingCacheVuln public target;
    bytes32 public lastKey;
    bytes public lastData;

    constructor(ValidatingCacheVuln _t) { target = _t; }

    function poison(bytes32 key, bytes calldata fake) external {
        target.setCache(key, fake);
    }

    function capture(bytes32 key) external {
        lastKey = key;
        lastData = target.cacheData(key);
    }

    function replay() external {
        target.setCache(lastKey, lastData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE CACHE WITH TTL VALIDATION
///    • Defense: TTLValidation – reject entries older than TTL
///─────────────────────────────────────────────────────────────────────────────
contract ValidatingCacheSafeTTL {
    mapping(bytes32 => bytes) public cacheData;
    mapping(bytes32 => uint256) public cacheTime;
    uint256 public constant TTL = 1 hours;

    event CacheRetrieved(
        address indexed who,
        bytes32           key,
        bytes             data,
        ValidatingCacheDefenseType defense
    );

    error VC__EntryExpired();

    function setCache(bytes32 key, bytes calldata data) external {
        cacheData[key] = data;
        cacheTime[key] = block.timestamp;
    }

    function getCache(bytes32 key) external {
        uint256 t = cacheTime[key];
        if (block.timestamp > t + TTL) revert VC__EntryExpired();
        emit CacheRetrieved(msg.sender, key, cacheData[key], ValidatingCacheDefenseType.TTLValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE CACHE WITH SIGNATURE VALIDATION
///    • Defense: SignatureValidation – require oracle signature on (key||data)
///─────────────────────────────────────────────────────────────────────────────
contract ValidatingCacheSafeSig {
    mapping(bytes32 => bytes) public cacheData;
    address public oracle;

    event CacheRetrieved(
        address indexed who,
        bytes32           key,
        bytes             data,
        ValidatingCacheDefenseType defense
    );

    constructor(address _oracle) {
        oracle = _oracle;
    }

    function setCache(
        bytes32 key,
        bytes calldata data,
        bytes calldata sig
    ) external {
        // verify signature over key||data
        bytes32 msgHash = keccak256(abi.encodePacked(key, data));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != oracle) revert VC__InvalidSignature();
        cacheData[key] = data;
    }

    function getCache(bytes32 key) external {
        emit CacheRetrieved(msg.sender, key, cacheData[key], ValidatingCacheDefenseType.SignatureValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED CACHE WITH RATE-LIMIT & PURGE
///    • Defense: RateLimit – cap gets per block  
///               CachePurge – manual or automatic invalidation
///─────────────────────────────────────────────────────────────────────────────
contract ValidatingCacheSafeAdvanced {
    mapping(bytes32 => bytes) public cacheData;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public getsInBlock;
    uint256 public constant MAX_GETS = 5;

    event CacheRetrieved(
        address indexed who,
        bytes32           key,
        bytes             data,
        ValidatingCacheDefenseType defense
    );
    event CachePurged(
        bytes32           key,
        ValidatingCacheDefenseType defense
    );

    error VC__TooManyRequests();

    function setCache(bytes32 key, bytes calldata data) external {
        cacheData[key] = data;
    }

    function getCache(bytes32 key) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            getsInBlock[msg.sender] = 0;
        }
        getsInBlock[msg.sender]++;
        if (getsInBlock[msg.sender] > MAX_GETS) revert VC__TooManyRequests();
        emit CacheRetrieved(msg.sender, key, cacheData[key], ValidatingCacheDefenseType.RateLimit);
    }

    /// purge stale or invalid entries
    function purgeCache(bytes32 key) external {
        delete cacheData[key];
        emit CachePurged(key, ValidatingCacheDefenseType.CachePurge);
    }
}
