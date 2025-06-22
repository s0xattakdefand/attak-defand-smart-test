// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunicationsRouter {
    address public admin;
    uint32 public domainId;

    mapping(bytes32 => bool) public usedMessageIds;
    mapping(uint32 => address) public domainGateways;

    event MessageRouted(
        bytes32 indexed messageId,
        uint32 indexed fromDomain,
        address indexed target,
        bytes4 selector
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(uint32 _domainId) {
        admin = msg.sender;
        domainId = _domainId;
    }

    function setGateway(uint32 fromDomain, address gateway) external onlyAdmin {
        domainGateways[fromDomain] = gateway;
    }

    function routeMessage(
        bytes32 messageId,
        uint32 fromDomain,
        address target,
        bytes calldata payload
    ) external {
        require(!usedMessageIds[messageId], "Replay detected");
        require(domainGateways[fromDomain] == msg.sender, "Unauthorized sender");

        usedMessageIds[messageId] = true;

        (bool success, ) = target.call(payload);
        require(success, "Call failed");

        emit MessageRouted(messageId, fromDomain, target, bytes4(payload[:4]));
    }
}
