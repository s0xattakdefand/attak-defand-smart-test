// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
}

interface IENSResolver {
    function addr(bytes32 node) external view returns (address);
}

contract ENSProxyForwardResolver {
    IENSRegistry public ens;

    constructor(address _ens) {
        ens = IENSRegistry(_ens);
    }

    function resolveENS(string calldata name) external view returns (address) {
        bytes32 node = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(name)))); // Simplified namehash for "name.eth"
        address resolverAddr = ens.resolver(node);
        require(resolverAddr != address(0), "No resolver found");

        return IENSResolver(resolverAddr).addr(node);
    }
}
