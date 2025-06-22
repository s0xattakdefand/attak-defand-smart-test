// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract AlarisMaintenance is Initializable, UUPSUpgradeable, AccessControlUpgradeable {
    bytes32 public constant MAINTAINER_ROLE = keccak256("MAINTAINER_ROLE");

    uint256 public systemVersion;
    string public systemStatus;

    event SystemMaintained(uint256 version, string status);

    /// @notice Initializer function (replaces constructor)
    function initialize(address maintainer) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MAINTAINER_ROLE, maintainer);

        systemVersion = 1;
        systemStatus = "Initialized";
    }

    /// @notice Perform secure system maintenance or updates
    function performMaintenance(string calldata newStatus) external onlyRole(MAINTAINER_ROLE) {
        systemVersion += 1;
        systemStatus = newStatus;

        emit SystemMaintained(systemVersion, newStatus);
    }

    /// @notice Authorization function required by UUPS pattern
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
