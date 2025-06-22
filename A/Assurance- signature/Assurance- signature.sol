// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SignatureAssuranceVerifier {
    address public admin;
    mapping(address => bytes32) public userChallenges;
    mapping(bytes32 => bool) public usedAssuranceIds;

    event ChallengeIssued(address indexed user, bytes32 challenge);
    event SignatureVerified(address indexed user, bytes32 assuranceId);

    constructor() {
        admin = msg.sender;
    }

    /// Issue a challenge nonce to a user
    function issueChallenge(address user) external returns (bytes32 challenge) {
        challenge = keccak256(abi.encodePacked(user, block.timestamp, address(this)));
        userChallenges[user] = challenge;
        emit ChallengeIssued(user, challenge);
    }

    /// Verify signature and register assurance
    function verifySignature(
        address user,
        bytes calldata signature
    ) external returns (bytes32 assuranceId) {
        bytes32 challenge = userChallenges[user];
        require(challenge != 0, "No challenge issued");

        bytes32 ethSigned = ECDSA.toEthSignedMessageHash(challenge);
        address recovered = ECDSA.recover(ethSigned, signature);
        require(recovered == user, "Signature invalid");

        assuranceId = keccak256(abi.encodePacked(user, challenge));
        usedAssuranceIds[assuranceId] = true;

        emit SignatureVerified(user, assuranceId);
        delete userChallenges[user];
    }

    function hasAssuredSignature(bytes32 id) external view returns (bool) {
        return usedAssuranceIds[id];
    }
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(h, v, r, s);
    }
}
