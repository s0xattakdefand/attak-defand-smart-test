pragma solidity ^0.8.21;

interface SensitiveContract {
    function sensitiveAction() external;
}

contract UnauthorizedIntrusion {
    SensitiveContract public victim;

    constructor(address _victim) {
        victim = SensitiveContract(_victim);
    }

    function attemptIntrusion() external {
        victim.sensitiveAction();
    }
}
