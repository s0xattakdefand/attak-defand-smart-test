// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttackSurfaceMonitor - Detects and manages attack surfaces in a contract

contract AttackSurfaceMonitor {
    address public owner;
    mapping(bytes4 => bool) public exposedSelectors;
    mapping(address => bool) public trustedCallers;

    event SurfaceExposed(bytes4 indexed selector);
    event SurfaceAccessed(address indexed caller, bytes4 selector);
    event SurfaceBlocked(address indexed caller, bytes4 selector);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerSurface(bytes4 selector) external onlyOwner {
        exposedSelectors[selector] = true;
        emit SurfaceExposed(selector);
    }

    function addTrustedCaller(address caller) external onlyOwner {
        trustedCallers[caller] = true;
    }

    function monitorAccess(bytes calldata payload) external returns (bool) {
        if (payload.length < 4) revert("Invalid call");
        bytes4 selector = bytes4(payload[:4]);

        if (exposedSelectors[selector]) {
            if (!trustedCallers[msg.sender]) {
                emit SurfaceBlocked(msg.sender, selector);
                revert("Unauthorized surface access");
            }
            emit SurfaceAccessed(msg.sender, selector);
            return true;
        }

        return false;
    }

    // Simulated function that’s protected
    function sensitiveFunction(bytes calldata payload) external {
        require(monitorAccess(payload), "Access denied");
        // Protected logic here
    }
}
