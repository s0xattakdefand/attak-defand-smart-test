// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IOracleVerifier {
    function verify(bytes calldata data) external view returns (bool);
}

contract UniversalCacheRegistry is Ownable {
    using ECDSA for bytes32;

    struct CacheEntry {
        bytes data;
        uint256 expiresAt;
        uint256 updatedAt;
    }

    mapping(bytes32 => CacheEntry) public cache;
    mapping(bytes32 => address) public updateTriggers;
    mapping(bytes32 => uint256) public ttl;

    event CacheUpdated(bytes32 indexed key, bytes data, uint256 expiresAt);
    event CacheInvalidated(bytes32 indexed key);
    event TTLSet(bytes32 indexed key, uint256 ttl);
    event TriggerSet(bytes32 indexed key, address trigger);

    constructor(address initialOwner) Ownable(initialOwner) {}

    modifier validTTL(bytes32 key) {
        require(
            block.timestamp <= cache[key].expiresAt,
            "[Cache] Entry expired"
        );
        _;
    }

    function setTTL(bytes32 key, uint256 duration) external onlyOwner {
        ttl[key] = duration;
        emit TTLSet(key, duration);
    }

    function setTrigger(bytes32 key, address trigger) external onlyOwner {
        updateTriggers[key] = trigger;
        emit TriggerSet(key, trigger);
    }

    function updateCache(bytes32 key, bytes memory data) public {
        require(
            msg.sender == owner() || msg.sender == updateTriggers[key],
            "[Cache] Unauthorized updater"
        );
        uint256 expiry = block.timestamp + ttl[key];
        cache[key] = CacheEntry({data: data, updatedAt: block.timestamp, expiresAt: expiry});
        emit CacheUpdated(key, data, expiry);
    }

    function invalidateCache(bytes32 key) external {
        require(
            msg.sender == owner() || msg.sender == updateTriggers[key],
            "[Cache] Unauthorized invalidation"
        );
        cache[key].expiresAt = block.timestamp;
        emit CacheInvalidated(key);
    }

    function get(bytes32 key) external view validTTL(key) returns (bytes memory) {
        return cache[key].data;
    }

    function getMetadata(bytes32 key) external view returns (uint256 updatedAt, uint256 expiresAt) {
        return (cache[key].updatedAt, cache[key].expiresAt);
    }

    function verifyAndUpdateWithOracle(
        bytes32 key,
        bytes calldata data,
        address oracleVerifier
    ) external {
        require(IOracleVerifier(oracleVerifier).verify(data), "[Cache] Oracle rejected data");
        updateCache(key, data);
    }

    function verifyAndUpdateWithSig(
        bytes32 key,
        bytes calldata data,
        bytes calldata sig,
        address signer
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(key, data, address(this))).toEthSignedMessageHash();
        require(hash.recover(sig) == signer, "[Cache] Invalid signature");
        updateCache(key, data);
    }
}
