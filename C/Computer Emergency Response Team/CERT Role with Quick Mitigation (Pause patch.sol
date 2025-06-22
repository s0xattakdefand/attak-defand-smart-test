// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * Defense scenario:
 * A contract with a 'CERT_ROLE' that can quickly pause or fix issues
 * - If an exploit is detected, the CERT calls `pause()` 
 *   to prevent further damage, then patches or routes a new version.
 */
contract CERTResponse is Pausable, AccessControl {
    bytes32 public constant CERT_ROLE = keccak256("CERT_ROLE");

    mapping(address => uint256) public balances;

    constructor(address admin, address certTeam) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CERT_ROLE, certTeam);
    }

    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @dev Called by the CERT to freeze all contract actions.
     */
    function emergencyPause() external onlyRole(CERT_ROLE) {
        _pause();
    }

    /**
     * @dev Called by the CERT to unpause once patched or safe again.
     */
    function endEmergency() external onlyRole(CERT_ROLE) {
        _unpause();
    }
}
