// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DiffieHellmanKey
 * @dev A smart contract for managing Diffie-Hellman key exchange sessions with a focus on key handling.
 * Supports public key registration, shared secret computation (simplified), and access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DiffieHellmanKey {
    // Struct to represent a Diffie-Hellman key exchange session
    struct KeyExchangeSession {
        string sessionName; // Name of the session (e.g., "Secure Key Exchange")
        string description; // Description of the session
        uint256 primeModulus; // Prime modulus (p) for Diffie-Hellman
        uint256 baseGenerator; // Base generator (g) for Diffie-Hellman
        address initiator; // Initiator of the session
        address responder; // Responder of the session
        uint256 initiatorPublicKey; // Initiator's public key (g^a mod p)
        uint256 responderPublicKey; // Responder's public key (g^b mod p)
        bool isActive; // Session active status
        bool exists; // Flag to check if session exists
    }

    // Mapping to store key exchange sessions by their unique ID
    mapping(bytes32 => KeyExchangeSession) public sessions;

    // Event emitted when a new key exchange session is created
    event SessionCreated(bytes32 indexed sessionId, string sessionName, address indexed initiator);
    // Event emitted when a responder joins a session
    event ResponderJoined(bytes32 indexed sessionId, address indexed responder);
    // Event emitted when a public key is registered
    event PublicKeyRegistered(bytes32 indexed sessionId, address indexed party, uint256 publicKey);
    // Event emitted when a session is updated
    event SessionUpdated(bytes32 indexed sessionId, string sessionName, bool isActive);

    // Modifier to check if the caller is the initiator
    modifier onlyInitiator(bytes32 sessionId) {
        require(sessions[sessionId].initiator == msg.sender, "Only the initiator can perform this action");
        require(sessions[sessionId].exists, "Session does not exist");
        _;
    }

    // Modifier to check if the caller is a participant (initiator or responder)
    modifier onlyParticipant(bytes32 sessionId) {
        require(sessions[sessionId].exists, "Session does not exist");
        require(
            sessions[sessionId].initiator == msg.sender || sessions[sessionId].responder == msg.sender,
            "Only participants can perform this action"
        );
        _;
    }

    /**
     * @dev Creates a new Diffie-Hellman key exchange session.
     * @param _sessionName The name of the session.
     * @param _description The description of the session.
     * @param _primeModulus The prime modulus (p) for Diffie-Hellman.
     * @param _baseGenerator The base generator (g) for Diffie-Hellman.
     * @param _initiatorPublicKey The initiator's public key (g^a mod p).
     * @return sessionId The unique ID of the created session.
     */
    function createSession(
        string memory _sessionName,
        string memory _description,
        uint256 _primeModulus,
        uint256 _baseGenerator,
        uint256 _initiatorPublicKey
    ) public returns (bytes32) {
        require(_primeModulus > 1, "Prime modulus must be greater than 1");
        require(_baseGenerator > 0 && _baseGenerator < _primeModulus, "Invalid base generator");
        require(_initiatorPublicKey > 0, "Invalid initiator public key");

        // Generate a unique ID for the session
        bytes32 sessionId = keccak256(abi.encodePacked(_sessionName, msg.sender, block.timestamp));
        
        // Ensure the session doesn't already exist
        require(!sessions[sessionId].exists, "Session with this ID already exists");

        // Initialize the session
        KeyExchangeSession storage newSession = sessions[sessionId];
        newSession.sessionName = _sessionName;
        newSession.description = _description;
        newSession.primeModulus = _primeModulus;
        newSession.baseGenerator = _baseGenerator;
        newSession.initiator = msg.sender;
        newSession.initiatorPublicKey = _initiatorPublicKey;
        newSession.isActive = true;
        newSession.exists = true;

        // Emit event for session creation
        emit SessionCreated(sessionId, _sessionName, msg.sender);

        return sessionId;
    }

    /**
     * @dev Allows a responder to join a session and register their public key.
     * @param _sessionId The ID of the session.
     * @param _responderPublicKey The responder's public key (g^b mod p).
     */
    function joinSession(bytes32 _sessionId, uint256 _responderPublicKey) public {
        require(sessions[_sessionId].exists, "Session does not exist");
        require(sessions[_sessionId].responder == address(0), "Responder already set");
        require(_responderPublicKey > 0, "Invalid responder public key");
        require(msg.sender != sessions[_sessionId].initiator, "Initiator cannot be responder");

        sessions[_sessionId].responder = msg.sender;
        sessions[_sessionId].responderPublicKey = _responderPublicKey;

        // Emit events for responder joining and public key registration
        emit ResponderJoined(_sessionId, msg.sender);
        emit PublicKeyRegistered(_sessionId, msg.sender, _responderPublicKey);
    }

    /**
     * @dev Updates the description or active status of a session.
     * @param _sessionId The ID of the session.
     * @param _newDescription The new description for the session.
     * @param _isActive The new active status.
     */
    function updateSession(bytes32 _sessionId, string memory _newDescription, bool _isActive) public onlyInitiator(_sessionId) {
        sessions[_sessionId].description = _newDescription;
        sessions[_sessionId].isActive = _isActive;

        // Emit event for session update
        emit SessionUpdated(_sessionId, sessions[_sessionId].sessionName, _isActive);
    }

    /**
     * @dev Simulates computing the shared secret key for a participant (simplified).
     * @param _sessionId The ID of the session.
     * @param _privateKey The private key of the caller (off-chain input).
     * @return sharedSecret The computed shared secret (simplified).
     */
    function computeSharedSecret(bytes32 _sessionId, uint256 _privateKey) public view onlyParticipant(_sessionId) returns (uint256) {
        require(sessions[_sessionId].exists, "Session does not exist");
        require(sessions[_sessionId].initiatorPublicKey > 0 && sessions[_sessionId].responderPublicKey > 0, "Both public keys must be set");

        // Determine the other party's public key
        uint256 otherPublicKey = (msg.sender == sessions[_sessionId].initiator)
            ? sessions[_sessionId].responderPublicKey
            : sessions[_sessionId].initiatorPublicKey;

        // Simplified modular exponentiation (actual computation should be off-chain or via oracle)
        // sharedSecret = otherPublicKey^privateKey mod primeModulus
        // Due to Solidity limitations, we return a placeholder (real computation requires external libraries)
        uint256 sharedSecret = otherPublicKey % sessions[_sessionId].primeModulus;

        return sharedSecret;
    }

    /**
     * @dev Retrieves the details of a key exchange session.
     * @param _sessionId The ID of the session.
     * @return sessionName The name of the session.
     * @return description The description of the session.
     * @return primeModulus The prime modulus.
     * @return baseGenerator The base generator.
     * @return initiator The initiator's address.
     * @return responder The responder's address.
     * @return initiatorPublicKey The initiator's public key.
     * @return responderPublicKey The responder's public key.
     * @return isActive The session's active status.
     */
    function getSession(bytes32 _sessionId)
        public
        view
        onlyParticipant(_sessionId)
        returns (
            string memory sessionName,
            string memory description,
            uint256 primeModulus,
            uint256 baseGenerator,
            address initiator,
            address responder,
            uint256 initiatorPublicKey,
            uint256 responderPublicKey,
            bool isActive
        )
    {
        require(sessions[_sessionId].exists, "Session does not exist");
        KeyExchangeSession storage session = sessions[_sessionId];
        return (
            session.sessionName,
            session.description,
            session.primeModulus,
            session.baseGenerator,
            session.initiator,
            session.responder,
            session.initiatorPublicKey,
            session.responderPublicKey,
            session.isActive
        );
    }
}