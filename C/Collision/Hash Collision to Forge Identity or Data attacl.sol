// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive contract that references data solely by a short hashed ID 
 * (like keccak256 of a small field).
 * Attack: if attacker finds 2 inputs that produce same shortHash => collision => forging data reference.
 */
contract NaiveHashID {
    mapping(bytes32 => string) public storedData;

    function storeData(string calldata data) external {
        // ❌ uses short or ambiguous hashing
        bytes32 shortHash = keccak256(abi.encodePacked(data));
        storedData[shortHash] = data;
    }

    function getData(string memory input) external view returns (string memory) {
        // re-hash
        bytes32 shortHash = keccak256(abi.encodePacked(input));
        return storedData[shortHash];
    }
}
