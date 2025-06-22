// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CaesarAEADVerifier {
    address public trustedSigner;

    event MessageVerified(address indexed sender, bytes32 messageHash);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    function verifyAEADProof(
        bytes32 ciphertextHash,
        bytes32 associatedDataHash,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 proofHash = keccak256(abi.encodePacked(ciphertextHash, associatedDataHash));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", proofHash));
        return recoverSigner(ethSigned, signature) == trustedSigner;
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
