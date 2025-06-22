// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IZKVerifier {
    function verify(bytes calldata proof, bytes32 input) external view returns (bool);
}

contract NATPoisoningZKRouter {
    IZKVerifier public verifier;

    mapping(address => address) public identityMap;  // alias → real
    mapping(address => bool) public poisonedAlias;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function registerAlias(address aliasAddr) external {
        identityMap[aliasAddr] = msg.sender;
    }

    function poisonAlias(address aliasAddr) external {
        // Simulate attacker overriding alias binding (e.g., bridge bug, mempool race)
        poisonedAlias[aliasAddr] = true;
    }

    function zkRelay(bytes calldata proof, bytes32 pubInput, address aliasAddr, address to, bytes calldata data) external {
        require(verifier.verify(proof, pubInput), "Invalid zkProof");
        require(!poisonedAlias[aliasAddr], "Alias poisoned");

        require(identityMap[aliasAddr] == msg.sender, "Not authorized");
        (bool ok, ) = to.call(data);
        require(ok, "Relay failed");
    }
}
