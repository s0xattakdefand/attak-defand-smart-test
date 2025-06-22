// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IZKReceiverVerifier {
    function verifyProof(bytes calldata zkProof, bytes32 publicInput) external view returns (bool);
}

contract zkMulticastRouter {
    IZKReceiverVerifier public verifier;

    constructor(address _verifier) {
        verifier = IZKReceiverVerifier(_verifier);
    }

    function zkMulticastCall(
        address[] calldata targets,
        bytes calldata payload,
        bytes[] calldata zkProofs,
        bytes32[] calldata inputs
    ) external {
        require(targets.length == zkProofs.length && zkProofs.length == inputs.length, "Array mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            require(verifier.verifyProof(zkProofs[i], inputs[i]), "ZK proof failed");

            (bool ok, ) = targets[i].call(payload);
            require(ok, "Call failed");
        }
    }
}

function mutateSelector(string memory fn) public pure returns (bytes4) {
    return bytes4(keccak256(bytes(fn)));
}

function multicastMutated(
    address[] calldata targets,
    string[] calldata funcs,
    bytes[] calldata args
) external {
    require(targets.length == funcs.length && funcs.length == args.length, "Mismatch");

    for (uint256 i = 0; i < targets.length; i++) {
        bytes memory callData = abi.encodePacked(mutateSelector(funcs[i]), args[i]);
        (bool ok, ) = targets[i].call(callData);
        require(ok, "Mutated call failed");
    }
}
