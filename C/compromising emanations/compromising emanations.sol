// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EmanationSafeContract {
    address public admin;
    mapping(address => bool) public privileged;
    uint256 public dummyGasSink;

    event AccessAttempt(address user, bool success, uint256 resultLength);

    constructor() {
        admin = msg.sender;
    }

    function setPrivileged(address user, bool isPrivileged) external {
        require(msg.sender == admin, "Only admin");
        privileged[user] = isPrivileged;
    }

    /// @notice Prevent branching-based gas inference
    function performSensitiveCheck() external returns (bytes memory paddedResponse) {
        bool access = privileged[msg.sender];
        uint256 sink;

        // Force both branches to consume equal gas
        if (access) {
            sink = _dummyLoop(100);
        } else {
            sink = _dummyLoop(100); // Same gas as if-branch
        }

        dummyGasSink = sink; // Store to force actual execution

        // Return fixed-size padded result
        bytes memory base = abi.encode(access);
        paddedResponse = _padTo(base, 64);
        emit AccessAttempt(msg.sender, access, paddedResponse.length);
    }

    function _dummyLoop(uint256 rounds) internal pure returns (uint256) {
        uint256 acc = 0;
        for (uint256 i = 0; i < rounds; i++) {
            acc += i;
        }
        return acc;
    }

    function _padTo(bytes memory input, uint256 targetLength) internal pure returns (bytes memory) {
        if (input.length >= targetLength) return input;
        bytes memory padded = new bytes(targetLength);
        for (uint256 i = 0; i < input.length; i++) {
            padded[i] = input[i];
        }
        return padded;
    }
}
