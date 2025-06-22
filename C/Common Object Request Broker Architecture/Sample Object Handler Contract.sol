// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HelloWorldHandler is IRequestHandler {
    function handleRequest(string calldata payload) external pure override returns (string memory) {
        return string(abi.encodePacked("Echo: ", payload));
    }
}
