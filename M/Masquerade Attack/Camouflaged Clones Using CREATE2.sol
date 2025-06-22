// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MasqueradeProxyFactory - Deploys fake clones at calculated addresses
contract MasqueradeProxyFactory {
    event MasqueradeClone(address indexed clone);

    function deploy(bytes memory bytecode, bytes32 salt) external returns (address clone) {
        assembly {
            clone := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(clone)) { revert(0, 0) }
        }
        emit MasqueradeClone(clone);
    }

    function predict(bytes memory bytecode, bytes32 salt) external view returns (address) {
        return address(uint160(uint(
            keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)))
        )));
    }
}
