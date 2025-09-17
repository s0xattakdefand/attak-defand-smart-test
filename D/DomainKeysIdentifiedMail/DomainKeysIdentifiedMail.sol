pragma solidity ^0.8.0;

// DKIM contract for managing DomainKeys Identified Mail key pairs and signatures
contract DKIM {
    // Struct to store DKIM key metadata
    struct DKIMKey {
        string domain; // Domain associated with the key (e.g., example.com)
        string selector; // DKIM selector (e.g., s1)
        string publicKey; // Public key for DKIM verification
        address owner; // Owner of the DKIM key
        uint256 registrationTime; // Timestamp of key registration
        bool isActive; // Status of the key (active or revoked)
        mapping(address => bool) authorizedVerifiers; // Access control for verification
    }

    // Struct to store email signature metadata
    struct EmailSignature {
        uint256 keyId; // Associated DKIM key ID
        string signatureHash; // Hash of the DKIM signature (e.g., SHA-256)
        string emailHash; // Hash of email content (header + body)
        uint256 timestamp; // Timestamp of signature registration
        bool isVerified; // Verification status
    }

    // Mapping from key ID to DKIMKey struct
    mapping(uint256 => DKIMKey) public dkimKeys;
    uint256 public keyCount; // Counter for DKIM key IDs

    // Mapping from signature ID to EmailSignature struct
    mapping(uint256 => EmailSignature) public emailSignatures;
    uint256 public signatureCount; // Counter for signature IDs

    // Event emitted when a new DKIM key is registered
    event KeyRegistered(uint256 keyId, string domain, string selector, address owner, uint256 registrationTime);
    // Event emitted when a key is revoked
    event KeyRevoked(uint256 keyId, string domain, address owner);
    // Event emitted when an email signature is registered
    event SignatureRegistered(uint256 signatureId, uint256 keyId, string signatureHash, uint256 timestamp);
    // Event emitted when a signature is verified
    event SignatureVerified(uint256 signatureId, uint256 keyId, address verifier);
    // Event emitted when access is granted to a verifier
    event AccessGranted(uint256 keyId, address verifier);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 keyId, address verifier);

    // Modifier to check if caller is the key owner
    modifier onlyKeyOwner(uint256 _keyId) {
        require(dkimKeys[_keyId].owner == msg.sender, "Only the key owner can perform this action");
        _;
    }

    // Modifier to check if key exists
    modifier keyExists(uint256 _keyId) {
        require(_keyId > 0 && _keyId <= keyCount, "DKIM key does not exist");
        _;
    }

    // Modifier to check if signature exists
    modifier signatureExists(uint256 _signatureId) {
        require(_signatureId > 0 && _signatureId <= signatureCount, "Signature does not exist");
        _;
    }

    // Function to register a new DKIM public key
    function registerKey(string memory _domain, string memory _selector, string memory _publicKey) public {
        keyCount++;
        DKIMKey storage newKey = dkimKeys[keyCount];
        newKey.domain = _domain;
        newKey.selector = _selector;
        newKey.publicKey = _publicKey;
        newKey.owner = msg.sender;
        newKey.registrationTime = block.timestamp;
        newKey.isActive = true;
        newKey.authorizedVerifiers[msg.sender] = true; // Owner gets verification access

        emit KeyRegistered(keyCount, _domain, _selector, msg.sender, block.timestamp);
    }

    // Function to revoke a DKIM key
    function revokeKey(uint256 _keyId) public onlyKeyOwner(_keyId) keyExists(_keyId) {
        require(dkimKeys[_keyId].isActive, "Key is already revoked");
        dkimKeys[_keyId].isActive = false;
        emit KeyRevoked(_keyId, dkimKeys[_keyId].domain, msg.sender);
    }

    // Function to register an email signature
    function registerSignature(uint256 _keyId, string memory _signatureHash, string memory _emailHash) public keyExists(_keyId) {
        require(dkimKeys[_keyId].isActive, "DKIM key is revoked");
        require(dkimKeys[_keyId].owner == msg.sender, "Only key owner can register signatures");

        signatureCount++;
        EmailSignature storage newSignature = emailSignatures[signatureCount];
        newSignature.keyId = _keyId;
        newSignature.signatureHash = _signatureHash;
        newSignature.emailHash = _emailHash;
        newSignature.timestamp = block.timestamp;
        newSignature.isVerified = false;

        emit SignatureRegistered(signatureCount, _keyId, _signatureHash, block.timestamp);
    }

    // Function to verify an email signature
    function verifySignature(uint256 _signatureId) public signatureExists(_signatureId) {
        uint256 keyId = emailSignatures[_signatureId].keyId;
        require(dkimKeys[keyId].isActive, "Associated DKIM key is revoked");
        require(dkimKeys[keyId].authorizedVerifiers[msg.sender], "Not authorized to verify");
        require(!emailSignatures[_signatureId].isVerified, "Signature already verified");

        // In a real implementation, cryptographic verification would occur off-chain
        // This contract assumes verification is done and marks it as verified
        emailSignatures[_signatureId].isVerified = true;
        emit SignatureVerified(_signatureId, keyId, msg.sender);
    }

    // Function to grant verification access to a DKIM key
    function grantAccess(uint256 _keyId, address _verifier) public onlyKeyOwner(_keyId) keyExists(_keyId) {
        require(_verifier != address(0), "Invalid verifier address");
        dkimKeys[_keyId].authorizedVerifiers[_verifier] = true;
        emit AccessGranted(_keyId, _verifier);
    }

    // Function to revoke verification access to a DKIM key
    function revokeAccess(uint256 _keyId, address _verifier) public onlyKeyOwner(_keyId) keyExists(_keyId) {
        require(_verifier != dkimKeys[_keyId].owner, "Cannot revoke owner's access");
        dkimKeys[_keyId].authorizedVerifiers[_verifier] = false;
        emit AccessRevoked(_keyId, _verifier);
    }

    // Function to check if a user has verification access
    function hasAccess(uint256 _keyId, address _verifier) public view keyExists(_keyId) returns (bool) {
        return dkimKeys[_keyId].authorizedVerifiers[_verifier];
    }

    // Function to get DKIM key metadata (only for authorized verifiers)
    function getKeyMetadata(uint256 _keyId) 
        public 
        view 
        keyExists(_keyId) 
        returns (string memory domain, string memory selector, string memory publicKey, address owner, uint256 registrationTime, bool isActive) 
    {
        require(dkimKeys[_keyId].authorizedVerifiers[msg.sender], "Access denied");
        DKIMKey storage key = dkimKeys[_keyId];
        return (key.domain, key.selector, key.publicKey, key.owner, key.registrationTime, key.isActive);
    }

    // Function to get email signature metadata (only for authorized verifiers of the associated key)
    function getSignatureMetadata(uint256 _signatureId) 
        public 
        view 
        signatureExists(_signatureId) 
        returns (uint256 keyId, string memory signatureHash, string memory emailHash, uint256 timestamp, bool isVerified) 
    {
        uint256 keyId = emailSignatures[_signatureId].keyId;
        require(dkimKeys[keyId].authorizedVerifiers[msg.sender], "Access denied");
        EmailSignature storage signature = emailSignatures[_signatureId];
        return (signature.keyId, signature.signatureHash, signature.emailHash, signature.timestamp, signature.isVerified);
    }

    // Function to transfer ownership of a DKIM key
    function transferOwnership(uint256 _keyId, address _newOwner) public onlyKeyOwner(_keyId) keyExists(_keyId) {
        require(_newOwner != address(0), "Invalid new owner address");
        dkimKeys[_keyId].owner = _newOwner;
        dkimKeys[_keyId].authorizedVerifiers[_newOwner] = true; // Grant access to new owner
    }
}
