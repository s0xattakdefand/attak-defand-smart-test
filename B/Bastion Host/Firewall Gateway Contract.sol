// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FirewallGateway {
    mapping(address => bool) public approvedGateways;
    address public owner;

    event GatewayApproved(address indexed gateway);
    event GatewayRevoked(address indexed gateway);
    event ProtectedCall(address indexed gateway, string message);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier onlyGateway() {
        require(approvedGateways[msg.sender], "Not an approved gateway");
        _;
    }

    function approveGateway(address gateway) public onlyOwner {
        approvedGateways[gateway] = true;
        emit GatewayApproved(gateway);
    }

    function revokeGateway(address gateway) public onlyOwner {
        approvedGateways[gateway] = false;
        emit GatewayRevoked(gateway);
    }

    function protectedFunction() public onlyGateway {
        // Only accessible by approved gateway addresses
        emit ProtectedCall(msg.sender, "Access granted to protected function");
    }
}
