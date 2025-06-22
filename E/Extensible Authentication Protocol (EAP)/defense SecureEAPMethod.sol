// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./EAPAuthenticator.sol";

contract SecureEAPMethod is IEAPMethod {
    using ECDSA for bytes32;

    address public trustedSigner;

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    /**
     * @notice The user must sign a message composed of (user, "EAP") off-chain.
     * The proof is the signature.
     */
    function verify(address user, bytes calldata proof) external view override returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(user, "EAP")).toEthSignedMessageHash();
        address recovered = messageHash.recover(proof);
        return (recovered == trustedSigner);
    }
}
