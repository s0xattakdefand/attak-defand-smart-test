// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title IEAPMethod
 * @notice Interface for authentication methods used by the EAPAuthenticator.
 */
interface IEAPMethod {
    function verify(address user, bytes calldata proof) external view returns (bool);
}

/**
 * @title EAPAuthenticator
 * @notice Implements an Extensible Authentication Protocol (EAP) framework
 * that allows an admin to register different authentication methods. Users then
 * authenticate by specifying a method ID and providing a corresponding proof.
 */
contract EAPAuthenticator is AccessControl {
    // For simplicity, we use the default admin role for administrative actions.
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    // Mapping of EAP method ID to the registered authentication method contract address.
    mapping(uint256 => address) public authMethods;
    
    event MethodRegistered(uint256 indexed methodId, address methodAddress);

    /**
     * @notice The constructor grants the ADMIN_ROLE to the specified admin address.
     * @param admin The address that will act as the administrator.
     */
    constructor(address admin) {
        _grantRole(ADMIN_ROLE, admin);
    }
    
    /**
     * @notice Registers an authentication method.
     * @param methodId A unique identifier for the authentication method.
     * @param methodAddress The address of the deployed authentication method contract.
     */
    function registerMethod(uint256 methodId, address methodAddress) external onlyRole(ADMIN_ROLE) {
        require(methodAddress != address(0), "Invalid method address");
        authMethods[methodId] = methodAddress;
        emit MethodRegistered(methodId, methodAddress);
    }
    
    /**
     * @notice Authenticates the caller using the specified method and proof.
     * @param methodId The identifier of the authentication method.
     * @param proof The authentication proof (the format depends on the method used).
     * @return True if authentication is successful; false otherwise.
     */
    function authenticate(uint256 methodId, bytes calldata proof) external view returns (bool) {
        address methodAddress = authMethods[methodId];
        require(methodAddress != address(0), "Method not registered");
        return IEAPMethod(methodAddress).verify(msg.sender, proof);
    }
}
