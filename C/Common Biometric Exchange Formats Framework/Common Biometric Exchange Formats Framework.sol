// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CBEFFBiometricRegistry {
    address public admin;

    struct BiometricRecord {
        bytes32 biometricHash;     // Hashed BDB (e.g., keccak256(BDB + salt))
        string formatType;         // SBH: "FaceScan", "Iris", etc.
        string formatOwner;        // SBH: "ISO", "VendorX"
        uint256 timestamp;         // Metadata timestamp
        bool verified;
    }

    mapping(address => BiometricRecord) public userBiometrics;
    mapping(address => bool) public authorizedProviders;

    event BiometricRegistered(address indexed user, string formatType, string formatOwner);
    event BiometricVerified(address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyProvider() {
        require(authorizedProviders[msg.sender], "Not authorized provider");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function authorizeProvider(address provider) external onlyAdmin {
        authorizedProviders[provider] = true;
    }

    function revokeProvider(address provider) external onlyAdmin {
        authorizedProviders[provider] = false;
    }

    // Register biometric hash + metadata (SBH+BDB)
    function registerBiometric(
        address user,
        bytes32 biometricHash,
        string calldata formatType,
        string calldata formatOwner
    ) external onlyProvider {
        require(userBiometrics[user].timestamp == 0, "Already registered");

        userBiometrics[user] = BiometricRecord({
            biometricHash: biometricHash,
            formatType: formatType,
            formatOwner: formatOwner,
            timestamp: block.timestamp,
            verified: false
        });

        emit BiometricRegistered(user, formatType, formatOwner);
    }

    // Optional manual verification (e.g., admin checks zkProof off-chain)
    function verifyBiometric(address user) external onlyAdmin {
        require(userBiometrics[user].timestamp > 0, "Not registered");
        userBiometrics[user].verified = true;

        emit BiometricVerified(user);
    }

    function getBiometricMetadata(address user) external view returns (
        bytes32 biometricHash,
        string memory formatType,
        string memory formatOwner,
        uint256 timestamp,
        bool verified
    ) {
        BiometricRecord memory rec = userBiometrics[user];
        return (rec.biometricHash, rec.formatType, rec.formatOwner, rec.timestamp, rec.verified);
    }
}
