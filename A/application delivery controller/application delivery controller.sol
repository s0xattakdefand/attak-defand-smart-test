// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Application Delivery Controller — Web3 Router Layer
contract AppDeliveryController {
    address public admin;
    bool public live = true;

    mapping(string => address) public routes; // action → handler
    mapping(address => bool) public blocked;

    event Routed(string action, address to);
    event Blocked(address user);
    event DeliveryFailed(address user, string action);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notBlocked() {
        require(!blocked[msg.sender], "Access denied");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setRoute(string calldata action, address handler) external onlyAdmin {
        routes[action] = handler;
    }

    function blockUser(address user) external onlyAdmin {
        blocked[user] = true;
        emit Blocked(user);
    }

    function toggle(bool state) external onlyAdmin {
        live = state;
    }

    function deliver(string calldata action, bytes calldata data) external notBlocked returns (bool success) {
        require(live, "ADC: Delivery off");
        address target = routes[action];
        require(target != address(0), "Route not found");

        (success, ) = target.call(data);
        if (!success) emit DeliveryFailed(msg.sender, action);
        else emit Routed(action, target);
    }
}
