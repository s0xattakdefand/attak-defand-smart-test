// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DefenseIndustrialBaseAttackDefense - Attack and Defense Simulation for Defense Industrial Base (DIB) in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Defense Industrial Base Registry (No Supplier Validation, No Hash Verification)
contract InsecureDIB {
    mapping(address => bool) public suppliers;
    mapping(address => bytes32) public componentHashes;

    event SupplierAdded(address supplier);
    event ComponentRegistered(address supplier, bytes32 componentHash);

    function addSupplier(address supplier) external {
        // 🔥 No vetting!
        suppliers[supplier] = true;
        emit SupplierAdded(supplier);
    }

    function registerComponent(address supplier, bytes32 componentHash) external {
        // 🔥 No verification
        require(suppliers[supplier], "Not a supplier");
        componentHashes[supplier] = componentHash;
        emit ComponentRegistered(supplier, componentHash);
    }
}

/// @notice Secure Defense Industrial Base Registry with Vetting, Hash Verification, and Role Management
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureDIB is AccessControl {
    bytes32 public constant SUPPLIER_ADMIN_ROLE = keccak256("SUPPLIER_ADMIN_ROLE");
    bytes32 public constant SUPPLIER_ROLE = keccak256("SUPPLIER_ROLE");

    mapping(address => bytes32) public componentHashes;

    event SupplierRegistered(address supplier);
    event ComponentHashRegistered(address supplier, bytes32 componentHash);

    constructor(address initialAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(SUPPLIER_ADMIN_ROLE, initialAdmin);
    }

    function registerSupplier(address supplier) external onlyRole(SUPPLIER_ADMIN_ROLE) {
        _grantRole(SUPPLIER_ROLE, supplier);
        emit SupplierRegistered(supplier);
    }

    function submitComponentHash(bytes32 componentHash) external onlyRole(SUPPLIER_ROLE) {
        require(componentHash != bytes32(0), "Invalid component hash");

        componentHashes[msg.sender] = componentHash;
        emit ComponentHashRegistered(msg.sender, componentHash);
    }

    function verifyComponent(address supplier, bytes32 expectedHash) external view returns (bool) {
        return componentHashes[supplier] == expectedHash;
    }
}

/// @notice Intruder trying to register fake suppliers or fake components
contract DIBIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeSupplier(address fakeSupplier) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("addSupplier(address)", fakeSupplier)
        );
    }

    function fakeComponentRegistration(address supplier, bytes32 fakeHash) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("registerComponent(address,bytes32)", supplier, fakeHash)
        );
    }
}
