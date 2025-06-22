// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DataFilter {
    uint256 public validRange = 100;

    // Accept only values below threshold
    function safeSubmit(uint256 amount) external pure returns (string memory) {
        require(amount <= 100, "Filtered: Amount too high");
        return "Accepted";
    }

    // Accept only whitelisted hashes
    bytes32 public allowedHash = keccak256(abi.encodePacked("whitelist"));

    function submitHash(string calldata input) external pure returns (bool) {
        bytes32 incoming = keccak256(abi.encodePacked(input));
        require(incoming == keccak256(abi.encodePacked("whitelist")), "Invalid input");
        return true;
    }
}
