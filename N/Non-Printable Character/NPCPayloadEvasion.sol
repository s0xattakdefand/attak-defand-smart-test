// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NPCPayloadEvasion {
    event DriftedPayload(address indexed attacker, bytes drifted);

    function craftPayload(bytes4 selector, bytes1 npc) external returns (bytes memory) {
        bytes memory drifted = abi.encodePacked(selector, npc);
        emit DriftedPayload(msg.sender, drifted);
        return drifted;
    }

    function sendDrift(address target, bytes calldata payload) external {
        (bool ok, ) = target.call(payload);
        require(ok, "NPC Drifted call failed");
    }
}
