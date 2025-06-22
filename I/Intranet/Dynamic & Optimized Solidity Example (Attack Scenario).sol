pragma solidity ^0.8.21;

interface PrivateNetwork {
    function confidentialAction() external;
}

contract UnauthorizedAccessAttack {
    PrivateNetwork public victim;

    constructor(address _victim) {
        victim = PrivateNetwork(_victim);
    }

    function attemptAccess() external {
        victim.confidentialAction();
    }
}
