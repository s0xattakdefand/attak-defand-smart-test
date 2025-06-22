// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BasicAuthBySignature {
    using ECDSA for bytes32;

    address public trustedBackend; // Backend service that signs messages
    mapping(address => bool) public authenticated;
    mapping(address => uint256) public latestNonce;

    event LoggedIn(address indexed user);
    event AuthRevoked(address indexed user);

    constructor(address _backendSigner) {
        trustedBackend = _backendSigner;
    }

    /**
     * @notice Authenticate a user with a signed message from the trusted backend.
     * @param user The address to authenticate.
     * @param nonce A unique number to prevent replay attacks.
     * @param signature The backend’s signature of the hash(user, nonce).
     */
    function loginWithSignature(
        address user,
        uint256 nonce,
        bytes memory signature
    ) public {
        require(nonce > latestNonce[user], "Nonce already used or too low");

        bytes32 hash = keccak256(abi.encodePacked(user, nonce));
        bytes32 ethSignedMessage = hash.toEthSignedMessageHash();

        address recovered = ethSignedMessage.recover(signature);
        require(recovered == trustedBackend, "Invalid signature");

        latestNonce[user] = nonce;
        authenticated[user] = true;

        emit LoggedIn(user);
    }

    /**
     * @notice Check if a user is authenticated.
     */
    function isLoggedIn(address user) public view returns (bool) {
        return authenticated[user];
    }

    /**
     * @notice Backend or user can revoke auth (optional).
     */
    function revokeAuth(address user) public {
        require(
            msg.sender == user || msg.sender == trustedBackend,
            "Only user or backend can revoke"
        );
        authenticated[user] = false;
        emit AuthRevoked(user);
    }

    /**
     * @notice Admin-only function to rotate backend signer.
     */
    function updateBackend(address newBackend) public {
        require(msg.sender == trustedBackend, "Only current backend can update");
        trustedBackend = newBackend;
    }
}
