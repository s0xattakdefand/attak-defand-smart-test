// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A safer approach:
 * - Use structured hashing (abi.encode) or typed data to avoid collisions
 * - Accept that Keccak-256 itself is collision-resistant for large data
 */
contract SafeHashID {
    mapping(bytes32 => string) public dataMap;

    /**
     * @dev Store data with a strongly structured hash 
     * that includes a user address or unique nonce
     */
    function storeData(
        string calldata content, 
        uint256 nonce
    ) external {
        // structured hashing => reduce collisions
        bytes32 safeHash = keccak256(abi.encode(msg.sender, content, nonce));
        dataMap[safeHash] = content;
    }

    function getData(bytes32 safeHash) external view returns (string memory) {
        // user must supply the hash directly
        return dataMap[safeHash];
    }
}
