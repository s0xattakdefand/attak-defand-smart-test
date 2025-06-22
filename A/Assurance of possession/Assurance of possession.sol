// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PossessionAssuranceVerifier - Verifies proof-of-possession via signature or token ownership

contract PossessionAssuranceVerifier {
    address public admin;
    mapping(address => bytes32) public currentChallenge;

    event ChallengeIssued(address indexed user, bytes32 challenge);
    event PossessionVerified(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    /// @notice Issues a new challenge nonce for user to sign
    function issueChallenge(address user) external returns (bytes32 challenge) {
        challenge = keccak256(abi.encodePacked(user, block.timestamp, address(this)));
        currentChallenge[user] = challenge;
        emit ChallengeIssued(user, challenge);
    }

    /// @notice Verifies that `user` signed the issued challenge with their private key
    function verifySignature(
        address user,
        bytes calldata signature
    ) external returns (bool) {
        bytes32 challenge = currentChallenge[user];
        require(challenge != 0, "No challenge");

        bytes32 ethSigned = ECDSA.toEthSignedMessageHash(challenge);
        address recovered = ECDSA.recover(ethSigned, signature);
        require(recovered == user, "Invalid signature");

        emit PossessionVerified(user);
        delete currentChallenge[user];
        return true;
    }
}

/// @dev Lightweight ECDSA helper
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}
