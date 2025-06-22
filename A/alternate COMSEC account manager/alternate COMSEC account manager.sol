// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AlternateCOMSECManager is AccessControl {
    bytes32 public constant PRIMARY_CAM_ROLE = keccak256("PRIMARY_CAM_ROLE");
    bytes32 public constant ALTERNATE_CAM_ROLE = keccak256("ALTERNATE_CAM_ROLE");

    struct KeyRecord {
        address keyAddress;
        bool isRevoked;
        uint256 timestamp;
    }

    mapping(address => KeyRecord) public keyRegistry;

    event KeyRegistered(address indexed key);
    event KeyRevoked(address indexed key, address revokedBy);
    event KeyRotated(address indexed oldKey, address indexed newKey, address rotatedBy);

    constructor(address primary, address alternate) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PRIMARY_CAM_ROLE, primary);
        _grantRole(ALTERNATE_CAM_ROLE, alternate);
    }

    modifier onlyCAM() {
        require(
            hasRole(PRIMARY_CAM_ROLE, msg.sender) || hasRole(ALTERNATE_CAM_ROLE, msg.sender),
            "Not authorized CAM"
        );
        _;
    }

    function registerKey(address key) external onlyRole(PRIMARY_CAM_ROLE) {
        require(key != address(0), "Invalid key");
        keyRegistry[key] = KeyRecord({keyAddress: key, isRevoked: false, timestamp: block.timestamp});
        emit KeyRegistered(key);
    }

    function revokeKey(address key) external onlyCAM {
        require(keyRegistry[key].keyAddress != address(0), "Key not found");
        keyRegistry[key].isRevoked = true;
        emit KeyRevoked(key, msg.sender);
    }

    function rotateKey(address oldKey, address newKey) external onlyCAM {
        require(!keyRegistry[oldKey].isRevoked, "Old key already revoked");
        keyRegistry[oldKey].isRevoked = true;
        keyRegistry[newKey] = KeyRecord({keyAddress: newKey, isRevoked: false, timestamp: block.timestamp});
        emit KeyRotated(oldKey, newKey, msg.sender);
    }

    function isKeyValid(address key) public view returns (bool) {
        return keyRegistry[key].keyAddress != address(0) && !keyRegistry[key].isRevoked;
    }

    function getKeyInfo(address key) public view returns (KeyRecord memory) {
        return keyRegistry[key];
    }
}
