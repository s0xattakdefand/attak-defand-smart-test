// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract zkBridgeReplayTrap {
    mapping(bytes32 => bool) public seenProofs;
    address public relayer;

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function relay(bytes calldata zkProof, bytes32 publicInput) external {
        require(msg.sender == relayer, "Invalid relayer");
        require(!seenProofs[publicInput], "Replay blocked");

        seenProofs[publicInput] = true;
        // 🔁 Real logic here (token transfer, voting, etc.)
    }
}
