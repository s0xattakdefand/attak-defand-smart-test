// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IZKVerifier {
    function verifyProof(bytes calldata zkProof, bytes32 publicInput) external view returns (bool);
}

contract ZKMetaTxGuarded {
    IZKVerifier public verifier;
    mapping(address => uint256) public nonces;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function relay(
        address from,
        address to,
        uint256 value,
        uint256 nonce,
        bytes calldata zkProof
    ) external {
        require(nonce == nonces[from], "Invalid nonce");

        bytes32 publicInput = keccak256(abi.encodePacked(from, to, value, nonce));
        require(verifier.verifyProof(zkProof, publicInput), "Invalid zkProof");

        nonces[from] += 1;

        (bool success, ) = to.call{value: value}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
