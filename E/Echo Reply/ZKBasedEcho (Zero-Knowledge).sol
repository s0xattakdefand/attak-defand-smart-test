// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKBasedEcho {
    IZKVerifier public verifier;

    event ZKEchoed(address indexed sender);

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function echoZK(bytes calldata zkProof) external {
        // The user proves knowledge of some message or data 
        // via a zero-knowledge proof, no raw data is echoed
        require(verifier.verifyProof(zkProof), "Invalid ZK proof");
        emit ZKEchoed(msg.sender);
    }
}
