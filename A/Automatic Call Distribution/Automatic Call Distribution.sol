// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Handler Injection, Misrouting, Drift
/// Defense Types: Routing Guard, Admin-only Control, Whitelist

contract ACDDispatcher {
    address public admin;

    mapping(string => address) public handlerRoutes;       // e.g., "upgrade" => UpgradeHandler
    mapping(address => bool) public approvedHandlers;

    event RouteSet(string action, address handler);
    event CallRouted(string action, address handler);
    event AttackDetected(address attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Admin sets handler for action
    function setRoute(string calldata action, address handler) external onlyAdmin {
        require(approvedHandlers[handler], "Handler not approved");
        handlerRoutes[action] = handler;
        emit RouteSet(action, handler);
    }

    /// DEFENSE: Approve handler
    function approveHandler(address handler) external onlyAdmin {
        approvedHandlers[handler] = true;
    }

    /// DEFENSE: Route to handler and delegatecall logic
    function routeAndExecute(string calldata action, bytes calldata data) external {
        address handler = handlerRoutes[action];
        require(handler != address(0), "No route set");

        (bool success, ) = handler.delegatecall(data);
        require(success, "Handler execution failed");

        emit CallRouted(action, handler);
    }

    /// ATTACK Simulation: Attempt to execute unapproved handler
    function attackInjectHandler(string calldata action, address rogueHandler) external {
        emit AttackDetected(msg.sender, "Handler injection attempt");
        revert("Blocked unauthorized handler injection");
    }

    /// View routing table
    function getRoute(string calldata action) external view returns (address) {
        return handlerRoutes[action];
    }
}
