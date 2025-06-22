// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AppInterconnectRouter {
    mapping(address => bool) public trustedApps;
    mapping(bytes32 => bool) public processedMessages;

    event Routed(address indexed from, string action, bytes payload);
    event Rejected(address indexed from, string reason);

    modifier onlyTrustedApp() {
        if (!trustedApps[msg.sender]) {
            emit Rejected(msg.sender, "Caller not trusted");
            revert("Untrusted interconnect");
        }
        _;
    }

    function registerApp(address app) external {
        trustedApps[app] = true;
    }

    function unregisterApp(address app) external {
        trustedApps[app] = false;
    }

    function route(
        string calldata action,
        bytes calldata payload,
        bytes32 messageHash
    ) external onlyTrustedApp {
        require(!processedMessages[messageHash], "Replay blocked");
        processedMessages[messageHash] = true;

        emit Routed(msg.sender, action, payload);
        // custom router logic here
    }

    function isProcessed(bytes32 hash) external view returns (bool) {
        return processedMessages[hash];
    }
}
