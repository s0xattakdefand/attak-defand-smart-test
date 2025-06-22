// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AddressSecurity {
    address public owner;
    mapping(address => bool) public whitelisted;

    event TransferredETH(address to, uint256 amount);
    event Whitelisted(address user);
    event Removed(address user);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyWhitelisted() {
        require(whitelisted[msg.sender], "Not whitelisted");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function whitelist(address user) external onlyOwner {
        whitelisted[user] = true;
        emit Whitelisted(user);
    }

    function remove(address user) external onlyOwner {
        delete whitelisted[user];
        emit Removed(user);
    }

    function transferETH(address payable to, uint256 amount) external onlyWhitelisted {
        require(address(this).balance >= amount, "Insufficient balance");
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "Transfer failed");
        emit TransferredETH(to, amount);
    }

    function isContract(address addr) external view returns (bool) {
        return addr.code.length > 0;
    }

    receive() external payable {}
}
