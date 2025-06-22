// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILegacyVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balanceOf(address user) external view returns (uint256);
}

contract CompensatingVaultWrapper {
    address public admin;
    address public legacyVault;
    bool public paused;
    uint256 public withdrawLimit;

    mapping(address => bool) public approvedUsers;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyApproved() {
        require(approvedUsers[msg.sender], "Not approved");
        _;
    }

    modifier notPaused() {
        require(!paused, "Vault paused");
        _;
    }

    constructor(address _legacyVault, uint256 _withdrawLimit) {
        admin = msg.sender;
        legacyVault = _legacyVault;
        withdrawLimit = _withdrawLimit;
    }

    function approveUser(address user) external onlyAdmin {
        approvedUsers[user] = true;
    }

    function revokeUser(address user) external onlyAdmin {
        approvedUsers[user] = false;
    }

    function pause() external onlyAdmin {
        paused = true;
    }

    function unpause() external onlyAdmin {
        paused = false;
    }

    function deposit() external payable notPaused onlyApproved {
        ILegacyVault(legacyVault).deposit{value: msg.value}();
    }

    function withdraw(uint256 amount) external notPaused onlyApproved {
        require(amount <= withdrawLimit, "Exceeds limit");
        ILegacyVault(legacyVault).withdraw(amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return ILegacyVault(legacyVault).balanceOf(user);
    }
}
