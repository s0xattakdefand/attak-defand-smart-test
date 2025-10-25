// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Eavesdropper {
    // Enum for Authenticator Assurance Levels (AAL)
    enum AAL { None, AAL1, AAL2, AAL3 }

    // Structure for secure session
    struct Session {
        address user; // User being authenticated
        AAL assuranceLevel; // AAL1, AAL2, or AAL3
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isActive; // Session status
        uint256 timestamp; // Creation time
        address attester; // Who created the session
    }

    // Mapping to store sessions by ID
    mapping(uint256 => Session) public sessions;
    // Mapping to track authorized attesters (e.g., authentication servers)
    mapping(address => bool) public authorizedAttesters;
    // Mapping to track active sessions per user
    mapping(address => uint256) public activeSessions;
    // Session counter
    uint256 public sessionCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event SessionCreated(uint256 indexed sessionId, address indexed attester, address indexed user, AAL assuranceLevel, bytes32 nonce);
    event BatchSessionCreated(uint256[] sessionIds, address attester);
    event SessionEnded(uint256 indexed sessionId, address indexed attester);
    event AttesterAuthorized(address indexed attester, bool authorized);

    // Modifier to restrict to admin
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Modifier to restrict to authorized attesters
    modifier onlyAuthorizedAttester() {
        require(authorizedAttesters[msg.sender] || msg.sender == admin, "Not an authorized attester");
        _;
    }

    // Constructor to set admin
    constructor() {
        admin = msg.sender;
        sessionCount = 0;
    }

    // Function to authorize attesters
    function authorizeAttester(address _attester, bool _status) external onlyAdmin {
        authorizedAttesters[_attester] = _status;
        emit AttesterAuthorized(_attester, _status);
    }

    // Function to initiate a secure session
    function initiateSecureSession(address _user, uint8 _aal, bytes32 _nonce) public onlyAuthorizedAttester returns (uint256) {
        require(_user != address(0), "Invalid user");
        require(_aal >= 1 && _aal <= 3, "Invalid AAL (must be 1, 2, or 3)");
        require(_nonce != bytes32(0), "Invalid nonce");
        require(activeSessions[_user] == 0, "User already has an active session");

        sessionCount++;
        sessions[sessionCount] = Session({
            user: _user,
            assuranceLevel: AAL(_aal),
            nonce: _nonce,
            isActive: true,
            timestamp: block.timestamp,
            attester: msg.sender
        });
        activeSessions[_user] = sessionCount;

        emit SessionCreated(sessionCount, msg.sender, _user, AAL(_aal), _nonce);
        return sessionCount;
    }

    // Function to initiate multiple secure sessions (batch)
    function batchInitiateSessions(address[] calldata _users, uint8[] calldata _aals, bytes32[] calldata _nonces) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(_users.length == _aals.length && _aals.length == _nonces.length, "Mismatched input arrays");
        require(_users.length > 0, "Empty batch");
        require(_users.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_users.length);

        for (uint256 i = 0; i < _users.length; i++) {
            ids[i] = initiateSecureSession(_users[i], _aals[i], _nonces[i]);
        }

        emit BatchSessionCreated(ids, msg.sender);
        return ids;
    }

    // Function to end a session
    function endSession(uint256 _sessionId) external {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        Session storage session = sessions[_sessionId];
        require(session.attester == msg.sender || msg.sender == admin, "Not authorized to end session");
        require(session.isActive, "Session already ended");

        session.isActive = false;
        activeSessions[session.user] = 0;
        emit SessionEnded(_sessionId, msg.sender);
    }

    // Function to verify session
    function verifySession(uint256 _sessionId) external view returns (string memory status, AAL assuranceLevel, bytes32 nonce) {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        Session memory session = sessions[_sessionId];
        return (session.isActive ? "Active" : "Ended", session.assuranceLevel, session.nonce);
    }

    // Function to get session details
    function getSession(uint256 _sessionId) external view returns (address attester, address user, AAL assuranceLevel, bytes32 nonce, bool isActive, uint256 timestamp) {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        Session memory session = sessions[_sessionId];
        return (session.attester, session.user, session.assuranceLevel, session.nonce, session.isActive, session.timestamp);
    }
}