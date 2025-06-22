// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttackSignatureGuard - Detects and blocks known malicious call signatures in smart contracts

contract AttackSignatureGuard {
    address public admin;
    mapping(bytes4 => bool) public blockedSelectors;
    mapping(bytes32 => bool) public flaggedPayloads;

    event SignatureBlocked(bytes4 selector);
    event PayloadFlagged(bytes32 hash, address caller);
    event AttackAttempt(address indexed origin, bytes4 selector);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function blockSelector(bytes4 selector) external onlyAdmin {
        blockedSelectors[selector] = true;
        emit SignatureBlocked(selector);
    }

    function flagPayload(bytes calldata payload) external onlyAdmin {
        bytes32 hash = keccak256(payload);
        flaggedPayloads[hash] = true;
        emit PayloadFlagged(hash, msg.sender);
    }

    function detect(bytes calldata payload) external returns (bool) {
        bytes4 selector;
        if (payload.length >= 4) {
            selector = bytes4(payload[:4]);
            if (blockedSelectors[selector]) {
                emit AttackAttempt(tx.origin, selector);
                revert("Blocked attack signature");
            }
        }

        bytes32 hash = keccak256(payload);
        if (flaggedPayloads[hash]) {
            emit AttackAttempt(tx.origin, selector);
            revert("Flagged malicious payload");
        }

        return true;
    }

    // Example function using signature guard
    function protectedFunction(bytes calldata payload) external {
        detect(payload);
        // Safe logic here...
    }
}
