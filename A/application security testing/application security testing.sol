// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SecurityTestTarget {
    address public admin;
    uint256 public balance;

    event Executed(address user, bytes4 selector, uint256 amount);
    event Blocked(address user, string reason);

    modifier onlyAdmin() {
        if (msg.sender != admin) {
            emit Blocked(msg.sender, "Unauthorized access");
            revert("Not admin");
        }
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function deposit() external payable {
        balance += msg.value;
        emit Executed(msg.sender, msg.sig, msg.value);
    }

    function withdraw(uint256 amount) external onlyAdmin {
        require(amount <= balance, "Overdraw");
        balance -= amount;
        payable(msg.sender).transfer(amount);
        emit Executed(msg.sender, msg.sig, amount);
    }

    function simulateReentrancy(address attacker) external {
        (bool success, ) = attacker.call(abi.encodeWithSignature("attack()"));
        require(success, "Reentrancy failed");
    }
}
