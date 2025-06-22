// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureAsymmetricUsage {
    address public trustedSigner;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    // ❌ Does NOT validate message integrity
    function verifySignature(address claimedUser, bytes memory signature) public view returns (bool) {
        // Fails to hash and check actual message content
        bytes32 fakeHash = keccak256(abi.encodePacked(claimedUser)); // weak!
        address recovered = recoverSigner(fakeHash, signature);
        return recovered == trustedSigner;
    }

    // Insecure recovery with wrong assumptions
    function recoverSigner(bytes32 hash, bytes memory signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(hash, v, r, s); // not using Ethereum's prefix!
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
