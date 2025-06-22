// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract zkGateway {
    address public verifier;

    constructor(address _verifier) {
        verifier = _verifier;
    }

    function gateway(address to, bytes calldata data, bytes calldata zkProof) external {
        require(IZKVerifier(verifier).verifyProof(zkProof), "Invalid ZK proof");

        (bool success, ) = to.call(data);
        require(success, "Forward failed");
    }
}
