// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ControlledAuthorityManager is AccessControl {
    bytes32 public constant CONAUTH_ROLE = keccak256("CONAUTH_ROLE");

    event AuthorityGranted(address indexed controller);
    event AuthorityRevoked(address indexed controller);
    event CriticalActionTriggered(address indexed by, string reason);

    constructor(address initialAuthority) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONAUTH_ROLE, initialAuthority);
    }

    modifier onlyCONAUTH() {
        require(hasRole(CONAUTH_ROLE, msg.sender), "Not controlling authority");
        _;
    }

    function grantAuthority(address controller) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(CONAUTH_ROLE, controller);
        emit AuthorityGranted(controller);
    }

    function revokeAuthority(address controller) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(CONAUTH_ROLE, controller);
        emit AuthorityRevoked(controller);
    }

    /// 🔐 Example critical action only CONAUTH can trigger
    function triggerCriticalAction(string calldata reason) external onlyCONAUTH {
        emit CriticalActionTriggered(msg.sender, reason);
        // Add critical logic here
    }
}
