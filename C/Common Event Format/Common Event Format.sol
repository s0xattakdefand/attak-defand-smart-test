// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CEFLogger {
    address public admin;

    enum Severity { Info, Warning, Error, Critical }

    event CEFLog(
        uint256 indexed timestamp,
        string deviceVendor,
        string deviceProduct,
        string eventType,
        address indexed actor,
        address indexed target,
        Severity severity,
        string message
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logEvent(
        string calldata eventType,
        address target,
        Severity severity,
        string calldata message
    ) external {
        emit CEFLog(
            block.timestamp,
            "Web3Org",            // deviceVendor
            "OnChainModule",      // deviceProduct
            eventType,
            msg.sender,
            target,
            severity,
            message
        );
    }
}
