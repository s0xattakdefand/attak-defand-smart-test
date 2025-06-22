pragma solidity ^0.8.21;

contract OneTimePrivilegedAction {
    mapping(address => bool) public hasUsed;

    function usePrivilege() external {
        require(!hasUsed[msg.sender], "Already used");
        hasUsed[msg.sender] = true;
        // Execute sensitive logic once
    }
}
