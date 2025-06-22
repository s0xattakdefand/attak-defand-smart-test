// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract OnChainForensicsLogger {
    address public admin;
    mapping(bytes4 => bool) public sensitiveSelectors;
    mapping(address => bool) public flagged;

    event ForensicLog(
        address indexed actor,
        bytes4 indexed selector,
        uint256 gasUsed,
        string action
    );

    event AbnormalBehaviorFlagged(address indexed actor, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logCall(bytes calldata payload) external {
        require(payload.length >= 4, "Invalid input");
        bytes4 selector = bytes4(payload[:4]);
        uint256 startGas = gasleft();

        emit ForensicLog(msg.sender, selector, startGas, "CALL");

        if (sensitiveSelectors[selector]) {
            flagged[msg.sender] = true;
            emit AbnormalBehaviorFlagged(msg.sender, "Triggered sensitive selector");
        }
    }

    function markSelector(bytes4 selector) external onlyAdmin {
        sensitiveSelectors[selector] = true;
    }

    function unmarkSelector(bytes4 selector) external onlyAdmin {
        sensitiveSelectors[selector] = false;
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }
}
