// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense Pattern: 
 * - Use structured hashing (abi.encode) 
 * - Include user address, nonce, domain string for collision-resistance
 */
contract SafeHashID {
    mapping(bytes32 => string) public dataMap;

    /**
     * @dev Store data with a strongly structured hash 
     * that includes a domain prefix, user address, and nonce,
     * drastically reducing collision risk or forging attempts.
     */
    function storeData(
        string calldata content, 
        uint256 nonce
    ) external {
        // domain prefix to further separate usage
        bytes32 safeHash = keccak256(
            abi.encode("SafeHashDomain", msg.sender, content, nonce)
        );

        dataMap[safeHash] = content;
    }

    function getData(bytes32 safeHash) external view returns (string memory) {
        return dataMap[safeHash];
    }
}
