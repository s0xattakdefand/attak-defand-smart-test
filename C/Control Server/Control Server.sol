// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ControlServerReceiver — Accepts signed control commands from an off-chain control server
contract ControlServerReceiver {
    using ECDSA for bytes32;

    address public controlServer;
    bool public paused;

    event Paused();
    event Unpaused();
    event CommandExecuted(string command, address indexed executor);

    modifier onlyControlServer(bytes32 hash, bytes memory sig) {
        address signer = hash.toEthSignedMessageHash().recover(sig);
        require(signer == controlServer, "Invalid control server signature");
        _;
    }

    constructor(address _server) {
        controlServer = _server;
    }

    function pause(bytes calldata sig) external onlyControlServer(keccak256("PAUSE"), sig) {
        paused = true;
        emit Paused();
        emit CommandExecuted("PAUSE", msg.sender);
    }

    function unpause(bytes calldata sig) external onlyControlServer(keccak256("UNPAUSE"), sig) {
        paused = false;
        emit Unpaused();
        emit CommandExecuted("UNPAUSE", msg.sender);
    }

    function executeAction(string calldata action, bytes calldata sig)
        external
        onlyControlServer(keccak256(abi.encodePacked(action)), sig)
    {
        emit CommandExecuted(action, msg.sender);
        // You can extend this with actual action logic
    }
}
