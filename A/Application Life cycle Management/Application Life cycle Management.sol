// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ApplicationLifecycleManager is AccessControl {
    bytes32 public constant DEV_ROLE = keccak256("DEV_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    enum AppStatus { Planned, Deployed, Active, Deprecated }

    string public appVersion;
    AppStatus public status;
    address public currentLogic; // for proxy management

    event AppStatusChanged(AppStatus newStatus);
    event LogicUpgraded(address indexed newLogic, string reason);
    event AppDeprecated(address by, string reason);

    constructor(string memory version) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DEV_ROLE, msg.sender);
        appVersion = version;
        status = AppStatus.Planned;
    }

    /// @notice Transition from plan → deploy → active
    function setStatus(AppStatus newStatus) external onlyRole(OPERATOR_ROLE) {
        require(uint8(newStatus) > uint8(status), "Invalid transition");
        status = newStatus;
        emit AppStatusChanged(newStatus);
    }

    /// @notice Upgrade app logic address (for proxy)
    function upgradeLogic(address newLogic, string calldata reason) external onlyRole(DEV_ROLE) {
        require(status == AppStatus.Active, "Not upgradable now");
        currentLogic = newLogic;
        emit LogicUpgraded(newLogic, reason);
    }

    /// @notice Deprecate the application permanently
    function deprecateApp(string calldata reason) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(status != AppStatus.Deprecated, "Already deprecated");
        status = AppStatus.Deprecated;
        emit AppDeprecated(msg.sender, reason);
    }

    /// @notice View current app metadata
    function getAppMeta() external view returns (string memory, AppStatus, address) {
        return (appVersion, status, currentLogic);
    }
}
