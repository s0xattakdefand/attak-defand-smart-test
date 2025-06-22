// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface IDestinationContract {
    function executeAction(address user, bytes calldata data) external returns (bool);
}

contract ApplicationGateway is AccessControl {
    bytes32 public constant GATEWAY_ADMIN = keccak256("GATEWAY_ADMIN");
    bytes32 public constant AUTHORIZED_CALLER = keccak256("AUTHORIZED_CALLER");

    mapping(address => bool) public allowedDestinations;

    event RequestForwarded(address indexed caller, address indexed destination, bool success);
    event DestinationAuthorized(address indexed destination);
    event DestinationRevoked(address indexed destination);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GATEWAY_ADMIN, msg.sender);
    }

    modifier onlyAllowedDestination(address destination) {
        require(allowedDestinations[destination], "Destination not authorized");
        _;
    }

    /// @notice Forward requests securely to authorized contracts
    function forwardRequest(address destination, bytes calldata data)
        external
        onlyRole(AUTHORIZED_CALLER)
        onlyAllowedDestination(destination)
        returns (bool)
    {
        require(data.length > 0, "No data provided");

        bool success = IDestinationContract(destination).executeAction(msg.sender, data);

        emit RequestForwarded(msg.sender, destination, success);
        return success;
    }

    /// @notice Dynamically authorize a destination contract
    function authorizeDestination(address destination) external onlyRole(GATEWAY_ADMIN) {
        allowedDestinations[destination] = true;
        emit DestinationAuthorized(destination);
    }

    /// @notice Dynamically revoke authorization for a destination contract
    function revokeDestination(address destination) external onlyRole(GATEWAY_ADMIN) {
        allowedDestinations[destination] = false;
        emit DestinationRevoked(destination);
    }

    /// @notice Check if a destination is authorized dynamically
    function isDestinationAuthorized(address destination) external view returns (bool) {
        return allowedDestinations[destination];
    }
}
