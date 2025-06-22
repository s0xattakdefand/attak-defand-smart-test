// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CFReDSLogRecorder {
    address public admin;
    mapping(bytes4 => bool) public knownMaliciousSelectors;
    mapping(address => bool) public flagged;

    event Recorded(address indexed sender, bytes4 selector, uint256 gasLeft);
    event Flagged(address indexed suspicious, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function record(bytes calldata payload) external {
        require(payload.length >= 4, "Invalid calldata");
        bytes4 selector = bytes4(payload[:4]);
        emit Recorded(msg.sender, selector, gasleft());

        if (knownMaliciousSelectors[selector]) {
            flagged[msg.sender] = true;
            emit Flagged(msg.sender, "Matched known CFReDS pattern");
        }
    }

    function addMaliciousSelector(bytes4 selector) external onlyAdmin {
        knownMaliciousSelectors[selector] = true;
    }

    function removeSelector(bytes4 selector) external onlyAdmin {
        knownMaliciousSelectors[selector] = false;
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }
}
