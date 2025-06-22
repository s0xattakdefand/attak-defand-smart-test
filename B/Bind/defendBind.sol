// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureBinder {
    mapping(address => string) public boundNames;
    mapping(address => bool) public hasBound;

    event Bound(address indexed user, string name);

    function bind(string calldata name) public {
        require(!hasBound[msg.sender], "Already bound");
        boundNames[msg.sender] = name;
        hasBound[msg.sender] = true;

        emit Bound(msg.sender, name);
    }

    function getMyBinding() public view returns (string memory) {
        return boundNames[msg.sender];
    }
}
