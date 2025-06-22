// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract DefenseVault {
    mapping(address => uint256) public balances;
    bool internal locked;

    event IntrusionDetected(address attacker);

    modifier nonReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) {
            emit IntrusionDetected(msg.sender);
            revert("Withdraw failed");
        }
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
