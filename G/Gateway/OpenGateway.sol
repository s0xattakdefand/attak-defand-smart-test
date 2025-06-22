// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OpenGateway {
    event Forwarded(address indexed to, bytes data);

    function gateway(address to, bytes calldata data) external {
        (bool success, ) = to.call(data);
        require(success, "Forward failed");
        emit Forwarded(to, data);
    }
}
