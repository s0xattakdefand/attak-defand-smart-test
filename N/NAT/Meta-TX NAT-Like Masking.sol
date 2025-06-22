// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MetaTxNAT {
    mapping(address => address) public identityMap;

    function register(address aliasAddr) external {
        identityMap[aliasAddr] = msg.sender;
    }

    function relay(address to, bytes calldata data, address aliasAddr) external {
        require(identityMap[aliasAddr] == msg.sender, "Not authorized");
        (bool ok, ) = to.call(data);
        require(ok, "Relay failed");
    }
}
