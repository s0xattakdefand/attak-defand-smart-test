pragma solidity ^0.8.21;

interface Victim {
    function handle(bytes calldata data) external;
}

contract MaliciousForwarder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function maliciousForward(bytes calldata data) external {
        Victim(target).handle(data);
    }
}
