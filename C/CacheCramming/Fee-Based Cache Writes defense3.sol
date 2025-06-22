// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeBasedCacheDefense {
    struct Entry {
        bytes data;
        uint256 expiresAt;
    }

    mapping(bytes32 => Entry) public cache;
    uint256 public cacheFee = 0.01 ether;
    uint256 public ttl = 10 minutes;

    event CacheWritten(bytes32 indexed key, address indexed writer);
    event CacheRead(bytes32 indexed key, bytes data);

    modifier paidEnough() {
        require(msg.value >= cacheFee, "Insufficient cache fee");
        _;
    }

    function setCacheFee(uint256 fee) external {
        cacheFee = fee;
    }

    function write(bytes32 key, bytes calldata data) external payable paidEnough {
        cache[key] = Entry({
            data: data,
            expiresAt: block.timestamp + ttl
        });

        emit CacheWritten(key, msg.sender);
    }

    function read(bytes32 key) external view returns (bytes memory) {
        require(block.timestamp <= cache[key].expiresAt, "Cache expired");
        return cache[key].data;
    }

    // Optional logging read if needed (not view)
    function readWithLog(bytes32 key) external returns (bytes memory) {
        require(block.timestamp <= cache[key].expiresAt, "Cache expired");
        emit CacheRead(key, cache[key].data);
        return cache[key].data;
    }
}
