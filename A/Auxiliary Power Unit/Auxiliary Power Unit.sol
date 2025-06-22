// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AuxiliaryPowerUnit {
    address public admin;
    bool public mainSystemActive = true;

    mapping(address => uint256) public emergencyWithdrawable;
    bool public emergencyMode = false;

    event EmergencyModeActivated(address indexed caller);
    event EmergencyWithdraw(address indexed user, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyInEmergency() {
        require(emergencyMode || !mainSystemActive, "System active");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Simulated pause from external contract or governance
    function simulateSystemFailure() external onlyAdmin {
        mainSystemActive = false;
    }

    function activateEmergencyMode() external onlyAdmin {
        emergencyMode = true;
        emit EmergencyModeActivated(msg.sender);
    }

    function emergencyDeposit() external payable {
        require(mainSystemActive, "Cannot deposit during failure");
        emergencyWithdrawable[msg.sender] += msg.value;
    }

    function emergencyWithdraw() external onlyInEmergency {
        uint256 amount = emergencyWithdrawable[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        emergencyWithdrawable[msg.sender] = 0;
        payable(msg.sender).transfer(amount);

        emit EmergencyWithdraw(msg.sender, amount);
    }

    receive() external payable {}
}
