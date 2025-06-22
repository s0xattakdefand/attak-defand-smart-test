pragma solidity ^0.8.21;

contract KillSwitch {
    bool public killed = false;
    address public admin;

    modifier notKilled() {
        require(!killed, "Killed");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function kill() external {
        require(msg.sender == admin, "Not admin");
        killed = true;
    }

    function doSomething() external notKilled {
        // Functionality here
    }
}
