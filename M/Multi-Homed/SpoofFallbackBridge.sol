// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SpoofFallbackBridge {
    address public bridgeAdmin;
    bool public reorgMode;

    constructor() {
        bridgeAdmin = msg.sender;
    }

    fallback() external payable {
        // 🧨 Simulated reorg entry point
        if (reorgMode) {
            (bool ok, ) = msg.sender.call(msg.data); // spoof fallback call
            require(ok, "Fallback spoof failed");
        }
    }

    function toggleReorg(bool status) external {
        require(msg.sender == bridgeAdmin, "Only admin");
        reorgMode = status;
    }

    function legitimateCall(bytes calldata payload) external {
        require(!reorgMode, "Bridge is reorged");
        (bool ok, ) = address(this).call(payload);
        require(ok, "Call failed");
    }

    receive() external payable {}
}
