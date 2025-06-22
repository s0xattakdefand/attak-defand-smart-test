pragma solidity ^0.8.21;

contract OneTimeActionPolicy {
    mapping(address => bool) public hasExecuted;

    event ExecutedOnce(address indexed user);

    function oneTimeAction() external {
        require(!hasExecuted[msg.sender], "Already executed");
        hasExecuted[msg.sender] = true;
        emit ExecutedOnce(msg.sender);
        // Single-use logic
    }
}
