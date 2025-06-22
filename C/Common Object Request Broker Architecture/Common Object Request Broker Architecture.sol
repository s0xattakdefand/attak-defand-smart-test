// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IRequestHandler {
    function handleRequest(string calldata payload) external returns (string memory response);
}

contract CORBARequestBroker {
    address public admin;
    mapping(bytes32 => address) public objectRegistry;

    event ObjectRegistered(bytes32 indexed objectId, address indexed handler);
    event RequestDispatched(bytes32 indexed objectId, string payload, string response);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Admin registers objects with their handler contract
    function registerObject(bytes32 objectId, address handler) external onlyAdmin {
        require(handler != address(0), "Invalid handler");
        objectRegistry[objectId] = handler;
        emit ObjectRegistered(objectId, handler);
    }

    // Dispatch request to the registered object
    function dispatchRequest(bytes32 objectId, string calldata payload) external returns (string memory) {
        address handler = objectRegistry[objectId];
        require(handler != address(0), "Handler not found");

        try IRequestHandler(handler).handleRequest(payload) returns (string memory response) {
            emit RequestDispatched(objectId, payload, response);
            return response;
        } catch {
            revert("Handler execution failed");
        }
    }

    // View the handler for an object ID
    function getHandler(bytes32 objectId) external view returns (address) {
        return objectRegistry[objectId];
    }
}
