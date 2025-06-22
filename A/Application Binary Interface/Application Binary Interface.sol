// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: ABI Confusion, Selector Spoofing, Fallback Drift
/// Defense Types: Selector Registry, ABI Length Checks, Decode Guarding

contract ABIValidationGuard {
    address public admin;

    mapping(bytes4 => string) public knownSignatures;
    mapping(address => bool) public trustedTargets;

    event SelectorRegistered(bytes4 indexed selector, string signature);
    event CallForwarded(address indexed to, bytes4 selector);
    event AttackDetected(address indexed caller, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Admin registers known safe selectors
    function registerSelector(string calldata signature) external onlyAdmin {
        bytes4 selector = bytes4(keccak256(bytes(signature)));
        knownSignatures[selector] = signature;
        emit SelectorRegistered(selector, signature);
    }

    /// DEFENSE: Admin allows forwarding to trusted contracts
    function allowTarget(address target) external onlyAdmin {
        trustedTargets[target] = true;
    }

    /// DEFENSE: Safe low-level call with ABI selector validation
    function forwardCall(address target, bytes calldata data) external {
        require(trustedTargets[target], "Untrusted target");
        require(data.length >= 4, "Invalid calldata");

        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        if (bytes(knownSignatures[selector]).length == 0) {
            emit AttackDetected(msg.sender, "Unknown selector used");
            revert("Selector not registered");
        }

        (bool success, ) = target.call(data);
        require(success, "Forwarded call failed");

        emit CallForwarded(target, selector);
    }

    /// ATTACK Simulation: Call with spoofed selector (matches known but wrong context)
    function attackSpoofedSelector(address target) external {
        bytes memory badData = abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), msg.sender, 100);
        (bool success, ) = target.call(badData);
        if (success) {
            emit AttackDetected(msg.sender, "Spoofed ABI selector succeeded");
        }
        revert("Attack simulated");
    }

    /// Utility: resolve selector for any signature
    function getSelector(string calldata sig) external pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }
}
