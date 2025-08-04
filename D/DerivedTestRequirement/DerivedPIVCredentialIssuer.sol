pragma solidity ^0.8.0;

/**
 * @title DerivedPIVCredentialIssuer
 * @dev A smart contract for issuing and managing Derived PIV Credentials on-chain.
 * Requirements (inspired by NIST SP 800-157):
 * - Only authorized issuers can issue credentials.
 * - Credentials are issued based on proof of possession of a valid PIV card.
 * - Credential lifecycle includes issuance, verification, and revocation.
 * - Events are emitted for auditing and traceability.
 */
contract DerivedPIVCredentialIssuer {
    // Struct to represent a Derived PIV Credential
    struct DerivedPIVCredential {
        address holder; // Address of the credential holder
        bytes32 pivCardHash; // Hash of the PIV card's public key or certificate
        uint256 issuanceTimestamp; // Timestamp of issuance
        bool isValid; // Credential validity status
    }

    // Mapping to store credentials by holder's address
    mapping(address => DerivedPIVCredential) public credentials;

    // Mapping to store authorized issuers
    mapping(address => bool) public authorizedIssuers;

    // Address of the contract owner (initial issuer)
    address private contractOwner;

    // Event for credential issuance
    event CredentialIssued(address indexed holder, bytes32 pivCardHash, uint256 timestamp);

    // Event for credential revocation
    event CredentialRevoked(address indexed holder, uint256 timestamp);

    // Event for issuer authorization changes
    event IssuerAuthorizationChanged(address indexed issuer, bool authorized);

    /**
     * @dev Constructor to set the contract owner as the initial issuer.
     * Requirement: Contract owner cannot be the zero address.
     */
    constructor() {
        require(msg.sender != address(0), "Contract owner cannot be the zero address");
        contractOwner = msg.sender;
        authorizedIssuers[msg.sender] = true;
        emit IssuerAuthorizationChanged(msg.sender, true);
    }

    /**
     * @dev Modifier to restrict functions to the contract owner.
     * Requirement: Only the contract owner can authorize issuers.
     */
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the contract owner");
        _;
    }

    /**
     * @dev Modifier to restrict functions to authorized issuers.
     * Requirement: Only authorized issuers can issue or revoke credentials.
     */
    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender], "Caller is not an authorized issuer");
        _;
    }

    /**
     * @dev Authorizes or deauthorizes an issuer.
     * @param _issuer The address to authorize or deauthorize.
     * @param _authorized True to authorize, false to deauthorize.
     * Requirement: Only the contract owner can call this function.
     */
    function setIssuerAuthorization(address _issuer, bool _authorized) public onlyOwner {
        require(_issuer != address(0), "Issuer cannot be the zero address");
        authorizedIssuers[_issuer] = _authorized;
        emit IssuerAuthorizationChanged(_issuer, _authorized);
    }

    /**
     * @dev Issues a Derived PIV Credential to a holder.
     * @param _holder The address of the credential holder.
     * @param _pivCardHash The hash of the PIV card's public key or certificate.
     * Requirement: Only authorized issuers can issue credentials.
     * Requirement: Holder address and PIV card hash must be valid.
     * Requirement: Credential must not already exist for the holder.
     */
    function issueCredential(address _holder, bytes32 _pivCardHash) public onlyAuthorizedIssuer {
        require(_holder != address(0), "Holder cannot be the zero address");
        require(_pivCardHash != bytes32(0), "PIV card hash cannot be empty");
        require(credentials[_holder].holder == address(0), "Credential already exists for this holder");

        credentials[_holder] = DerivedPIVCredential({
            holder: _holder,
            pivCardHash: _pivCardHash,
            issuanceTimestamp: block.timestamp,
            isValid: true
        });

        emit CredentialIssued(_holder, _pivCardHash, block.timestamp);
    }

    /**
     * @dev Revokes a Derived PIV Credential.
     * @param _holder The address of the credential holder.
     * Requirement: Only authorized issuers can revoke credentials.
     * Requirement: Credential must exist and be valid.
     */
    function revokeCredential(address _holder) public onlyAuthorizedIssuer {
        require(credentials[_holder].holder != address(0), "No credential exists for this holder");
        require(credentials[_holder].isValid, "Credential is already revoked");

        credentials[_holder].isValid = false;
        emit CredentialRevoked(_holder, block.timestamp);
    }

    /**
     * @dev Verifies a Derived PIV Credential.
     * @param _holder The address of the credential holder.
     * @param _pivCardHash The hash of the PIV card's public key or certificate.
     * @return bool True if the credential is valid and matches the provided hash.
     * Requirement: Credential must exist, be valid, and match the provided hash.
     */
    function verifyCredential(address _holder, bytes32 _pivCardHash) public view returns (bool) {
        DerivedPIVCredential memory credential = credentials[_holder];
        return credential.holder != address(0) &&
               credential.isValid &&
               credential.pivCardHash == _pivCardHash;
    }

    /**
     * @dev Stub for verifying a zero-knowledge proof of PIV card possession.
     * @param _holder The address of the credential holder.
     * @param _proof The zero-knowledge proof data (simplified for demonstration).
     * @return bool True if the proof is valid (stub implementation).
     * Note: In a production environment, integrate with a ZKP verifier like Groth16VerifierSig ().[](https://docs.privado.id/docs/smart-contracts/)
     */
    function verifyZKProof(address _holder, bytes calldata _proof) public view returns (bool) {
        // Simplified stub: In reality, this would verify a ZKP against a circuit (e.g., Groth16).
        // For demonstration, assume proof is valid if holder has a valid credential.
        return credentials[_holder].holder != address(0) && credentials[_holder].isValid;
    }

    /**
     * @dev Returns the contract owner.
     * @return address The address of the contract owner.
     */
    function getContractOwner() public view returns (address) {
        return contractOwner;
    }
}