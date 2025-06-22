// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

contract ControlledSpaceVault is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant DATA_SLOT = keccak256("vault.controlled.data.slot");

    event DataSet(address indexed by, bytes32 value);
    event AccessDenied(address indexed sender, string action);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, admin);
    }

    modifier onlyAdmin() {
        if (!hasRole(ADMIN_ROLE, msg.sender)) {
            emit AccessDenied(msg.sender, "onlyAdmin");
            revert("Not authorized");
        }
        _;
    }

    function setSecureData(bytes32 value) external onlyAdmin {
        StorageSlot.getBytes32Slot(DATA_SLOT).value = value;
        emit DataSet(msg.sender, value);
    }

    function getSecureData() external view onlyAdmin returns (bytes32) {
        return StorageSlot.getBytes32Slot(DATA_SLOT).value;
    }

    fallback() external payable {
        emit AccessDenied(msg.sender, "fallback");
        revert("Fallback not allowed");
    }

    receive() external payable {
        emit AccessDenied(msg.sender, "receive");
        revert("Ether not accepted");
    }
}
