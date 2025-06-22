// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConsensusValidator {
    address public admin;
    mapping(address => bool) public signerSet;
    uint256 public requiredQuorum;
    mapping(bytes32 => bool) public usedMessages;

    event MessageAccepted(bytes32 indexed msgHash);
    event SignerUpdated(address signer, bool status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor(address[] memory initialSigners, uint256 quorum) {
        admin = msg.sender;
        for (uint256 i = 0; i < initialSigners.length; i++) {
            signerSet[initialSigners[i]] = true;
        }
        requiredQuorum = quorum;
    }

    function updateSigner(address signer, bool status) external onlyAdmin {
        signerSet[signer] = status;
        emit SignerUpdated(signer, status);
    }

    function validateMessage(bytes32 msgHash, bytes[] calldata signatures) external {
        require(!usedMessages[msgHash], "Replay detected");

        uint256 validSignatures;
        for (uint256 i = 0; i < signatures.length; i++) {
            address recovered = recoverSigner(msgHash, signatures[i]);
            if (signerSet[recovered]) {
                validSignatures++;
            }
        }

        require(validSignatures >= requiredQuorum, "Not enough valid signers");
        usedMessages[msgHash] = true;

        emit MessageAccepted(msgHash);
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        return ECDSA.recover(ECDSA.toEthSignedMessageHash(hash), sig);
    }
}
