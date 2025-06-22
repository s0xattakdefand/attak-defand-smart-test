// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureAsymmetricCrypto {
    using ECDSA for bytes32;

    address public trustedSigner;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    // Securely verify signed message
    function verify(address user, uint256 nonce, bytes memory signature) public view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(user, nonce));
        bytes32 ethSignedMessage = messageHash.toEthSignedMessageHash(); // adds "\x19Ethereum Signed Message:\n32"

        address recovered = ethSignedMessage.recover(signature);
        return recovered == trustedSigner;
    }
}
