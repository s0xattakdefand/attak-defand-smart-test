// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BasicAuthBySignature {
    using ECDSA for bytes32;

    address public trustedBackend;
    mapping(address => bool) public authenticated;

    event LoggedIn(address indexed user);
    event AuthRevoked(address indexed user);

    constructor(address _backend) {
        trustedBackend = _backend;
    }

    function loginWithSignature(address user, uint256 nonce, bytes memory sig) public {
        bytes32 hash = keccak256(abi.encodePacked(user, nonce));
        bytes32 signedHash = hash.toEthSignedMessageHash(); // ✅ Fixed with ECDSA

        address recovered = signedHash.recover(sig);
        require(recovered == trustedBackend, "Invalid signature");

        authenticated[user] = true;
        emit LoggedIn(user);
    }

    function isLoggedIn(address user) public view returns (bool) {
        return authenticated[user];
    }

    function revokeAuth(address user) public {
        require(msg.sender == trustedBackend, "Not authorized");
        authenticated[user] = false;
        emit AuthRevoked(user);
    }
}
