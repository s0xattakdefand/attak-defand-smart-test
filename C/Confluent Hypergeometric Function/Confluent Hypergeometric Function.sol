// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfluentHypergeometricOracle {
    address public oracle;
    mapping(bytes32 => bool) public verifiedResults;

    event ResultSubmitted(bytes32 indexed hash, string result);

    constructor(address _oracle) {
        oracle = _oracle;
    }

    function submitResult(bytes32 hash, string calldata result) external {
        require(msg.sender == oracle, "Not authorized");
        require(keccak256(bytes(result)) == hash, "Hash mismatch");

        verifiedResults[hash] = true;
        emit ResultSubmitted(hash, result);
    }

    function isVerified(string calldata result) external view returns (bool) {
        return verifiedResults[keccak256(bytes(result))];
    }
}
