// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AppLayerAccessControl {
    mapping(bytes4 => bool) public allowedSelectors;
    mapping(address => bool) public trustedApps;

    event AppCallAllowed(address indexed caller, bytes4 selector);
    event AppCallBlocked(address indexed caller, bytes4 selector, string reason);

    modifier appFirewall(bytes calldata input) {
        bytes4 selector;
        assembly {
            selector := calldataload(input.offset)
        }

        if (!allowedSelectors[selector]) {
            emit AppCallBlocked(msg.sender, selector, "Selector not allowed");
            revert("AppLayer: blocked function");
        }

        if (!trustedApps[msg.sender]) {
            emit AppCallBlocked(msg.sender, selector, "Untrusted caller");
            revert("AppLayer: untrusted caller");
        }

        emit AppCallAllowed(msg.sender, selector);
        _;
    }

    function registerSelector(bytes4 sel) external {
        allowedSelectors[sel] = true;
    }

    function registerTrustedApp(address app) external {
        trustedApps[app] = true;
    }

    function executeAppCall(bytes calldata input) external appFirewall(input) returns (string memory) {
        // Example: decode and act on valid input
        return "Application Layer execution authorized.";
    }
}
