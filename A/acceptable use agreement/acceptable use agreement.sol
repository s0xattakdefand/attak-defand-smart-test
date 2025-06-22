// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Non-Compliant Usage, Fake Consent, Signature Replay
/// Defense Types: Signature Verification, Agreement Hash, Onchain Consent Registry

contract AcceptableUseAgreement {
    address public admin;
    bytes32 public immutable agreementHash;

    mapping(address => bool) public hasAccepted;
    mapping(bytes32 => bool) public usedSigHashes;

    event AgreementAccepted(address indexed user);
    event AccessGranted(address indexed user);
    event AttackDetected(address indexed attacker, string reason);

    constructor(string memory agreementText) {
        admin = msg.sender;
        agreementHash = keccak256(bytes(agreementText));
    }

    /// DEFENSE: User submits signature over the agreement
    function acceptAgreement(bytes calldata sig) external {
        require(!hasAccepted[msg.sender], "Already accepted");

        bytes32 message = keccak256(abi.encodePacked(msg.sender, agreementHash));
        bytes32 signedMessage = ECDSA.toEthSignedMessageHash(message);

        address signer = ECDSA.recover(signedMessage, sig);
        if (signer != msg.sender) {
            emit AttackDetected(msg.sender, "Invalid AUA signature");
            revert("Invalid signature");
        }

        hasAccepted[msg.sender] = true;
        usedSigHashes[signedMessage] = true;
        emit AgreementAccepted(msg.sender);
    }

    /// DEFENSE: Only users who accepted the agreement can proceed
    function protectedAction() external {
        require(hasAccepted[msg.sender], "Must accept AUA");
        emit AccessGranted(msg.sender);
    }

    /// ATTACK SIMULATION: Try calling protected function without signing
    function attackWithoutAUA() external {
        if (!hasAccepted[msg.sender]) {
            emit AttackDetected(msg.sender, "Attempted protected access without agreement");
            revert("Blocked: No agreement");
        }
    }
}

/// ECDSA lib (standalone)
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
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
