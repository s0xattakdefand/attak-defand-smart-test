// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract VerifiedWriteAccessCache is AccessControl {
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    struct Entry {
        bytes data;
        uint256 expiresAt;
    }

    mapping(bytes32 => Entry) public cache;
    uint256 public ttl = 10 minutes;

    event CacheWritten(bytes32 indexed key, address indexed writer);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function write(bytes32 key, bytes calldata data) external onlyRole(WRITER_ROLE) {
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

    function setTTL(uint256 newTTL) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ttl = newTTL;
    }
}
