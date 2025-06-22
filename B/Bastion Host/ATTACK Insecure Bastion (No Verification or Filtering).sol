// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureBastionForwarder {
    address public targetContract;

    constructor(address _target) {
        targetContract = _target;
    }

    // ❌ Forwards any call/data without authentication
    function forward(bytes calldata data) public {
        (bool success, ) = targetContract.call(data);
        require(success, "Forwarding failed");
    }
}
