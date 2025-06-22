// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack Pattern: Using naive hashing 
 * that can lead to collisions for short or ambiguous data.
 */
contract NaiveHashCollision {
    mapping(bytes32 => string) public storedData;

    /**
     * @dev Store data by hashing with keccak256(abi.encodePacked(data)).
     * This can lead to collisions if data is short or ambiguous,
     * or if attacker manipulates the way data is packed.
     */
    function storeData(string calldata data) external {
        bytes32 shortHash = keccak256(abi.encodePacked(data));
        storedData[shortHash] = data;
    }

    /**
     * @dev Reads data by recomputing the shortHash with the same naive approach.
     * Attackers might exploit collisions to forge an alternate input 
     * that yields the same shortHash, overshadowing the stored data.
     */
    function getData(string calldata input) external view returns (string memory) {
        bytes32 shortHash = keccak256(abi.encodePacked(input));
        return storedData[shortHash];
    }
}
