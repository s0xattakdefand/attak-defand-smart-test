// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MutatedMultiInterfaceRouter {
    function mutateSelector(string memory fn) public pure returns (bytes4) {
        return bytes4(keccak256(bytes(fn)));
    }

    function routeWithMutation(
        address target,
        string memory fnName,
        bytes memory args
    ) external {
        bytes memory payload = abi.encodePacked(mutateSelector(fnName), args);
        (bool ok, ) = target.call(payload);
        require(ok, "Mutated call failed");
    }
}
