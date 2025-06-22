// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NonRepudiationLog {
    event SignedAction(
        address indexed signer,
        bytes32 indexed actionHash,
        string actionType,
        uint256 timestamp
    );

    function record(bytes32 hash, string calldata actionType) external {
        emit SignedAction(msg.sender, hash, actionType, block.timestamp);
    }
}
