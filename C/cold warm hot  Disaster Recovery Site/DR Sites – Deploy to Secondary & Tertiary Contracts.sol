// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A 'Warm' or 'Hot' DR site approach:
 * - Keep a secondary contract up to date
 * - If primary fails, users can switch to secondary
 */
contract PrimaryContract {
    // If you want a 'hot' site, maintain in real-time
    address public secondaryDR; 
    mapping(address => uint256) public balances;

    // Admin or governance
    address public admin;

    event BackupSynced(address user, uint256 amount);

    constructor(address _admin, address _dr) {
        admin = _admin;
        secondaryDR = _dr;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        // Sync to DR site
        IDR(secondaryDR).syncBackup(msg.sender, balances[msg.sender]);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        // Sync to DR site
        IDR(secondaryDR).syncBackup(msg.sender, balances[msg.sender]);
    }

    // If the primary fails, we rely on the DR contract 
}

interface IDR {
    function syncBackup(address user, uint256 newBalance) external;
}
