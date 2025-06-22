// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title WeightedMultiCA
 * This contract illustrates how to require multiple CAs to sign off on a user's certificate.
 */
contract WeightedMultiCA {
    using ECDSA for bytes32;

    // Each CA has a weight
    mapping(address => uint8) public caWeights;
    // Required threshold for sum of weights in a multi-sign scenario
    uint8 public trustThreshold;

    struct CertRecord {
        bytes32 certHash;
        uint256 expiry;
    }

    mapping(address => CertRecord) public userCerts;

    event CAWeightSet(address ca, uint8 weight);
    event UserCertStored(address user, bytes32 certHash, uint256 expiry);

    constructor(uint8 _threshold) {
        trustThreshold = _threshold;
    }

    /**
     * @notice Set the weight for a given CA address.
     */
    function setCAWeight(address ca, uint8 weight) external {
        // In production, only an admin or governance would do this
        caWeights[ca] = weight;
        emit CAWeightSet(ca, weight);
    }

    /**
     * @notice Store a user certificate only if enough CAs sign it.
     * @param certHash  The hash of the user's certificate
     * @param expiry    The timestamp after which cert is invalid
     * @param caSigs    An array of signatures from different CAs
     * @param cas       The CA addresses corresponding to each signature
     */
    function storeCertificateMultiCA(
        bytes32 certHash,
        uint256 expiry,
        bytes[] calldata caSigs,
        address[] calldata cas
    ) external {
        require(expiry > block.timestamp, "Cert expired on arrival");
        require(caSigs.length == cas.length, "Mismatched sigs & addresses");

        uint8 sumWeights;
        // Recreate the message to be signed
        bytes32 message = keccak256(abi.encodePacked(msg.sender, certHash, expiry))
            .toEthSignedMessageHash();

        for (uint256 i = 0; i < cas.length; i++) {
            // Skip zero-weight CAs
            uint8 weight = caWeights[cas[i]];
            if (weight == 0) continue;

            // Recover the signer
            address recoveredCA = message.recover(caSigs[i]);
            require(recoveredCA == cas[i], "Signature mismatch");
            
            sumWeights += weight;
        }

        require(sumWeights >= trustThreshold, "Insufficient CA trust weight");

        // Store user's cert record
        userCerts[msg.sender] = CertRecord(certHash, expiry);
        emit UserCertStored(msg.sender, certHash, expiry);
    }

    /**
     * @notice Check if a user's certificate is still valid.
     */
    function isAuthenticated(address user) external view returns (bool) {
        CertRecord memory cert = userCerts[user];
        if (cert.certHash == bytes32(0)) return false;
        if (block.timestamp > cert.expiry) return false;
        return true;
    }
}
