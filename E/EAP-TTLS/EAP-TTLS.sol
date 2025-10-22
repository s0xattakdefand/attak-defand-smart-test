// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EAPTTLS {
    // Structure to store authentication session details
    struct AuthSession {
        address client;
        bool isAuthenticated;
        uint256 sessionStart;
        string innerAuthMethod; // e.g., PAP, MS-CHAPv2
    }

    // Mapping to store sessions by session ID
    mapping(uint256 => AuthSession) public sessions;
    // Mapping to track authorized servers
    mapping(address => bool) public authorizedServers;
    // Mapping to track if a client has an active session
    mapping(address => uint256) public activeSessions;
    // Session counter
    uint256 public sessionCount;

    // Admin address for managing servers
    address public admin;
    // Event for tunnel establishment
    event TunnelEstablished(uint256 indexed sessionId, address indexed client, string innerAuthMethod);
    // Event for authentication result
    event AuthResult(uint256 indexed sessionId, address indexed client, bool success);
    // Event for server authorization
    event ServerAuthorized(address indexed server, bool authorized);

    // Modifier to restrict to admin
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Constructor to set the admin
    constructor() {
        admin = msg.sender;
        sessionCount = 0;
    }

    // Function to authorize a server (e.g., RADIUS server)
    function authorizeServer(address _server, bool _status) external onlyAdmin {
        authorizedServers[_server] = _status;
        emit ServerAuthorized(_server, _status);
    }

    // Function to initiate EAP-TTLS tunnel and inner authentication
    function initiateTunnel(string calldata _innerAuthMethod) external returns (uint256) {
        require(authorizedServers[msg.sender] || msg.sender == admin, "Caller not authorized");
        require(activeSessions[msg.sender] == 0, "Client already has an active session");

        sessionCount++;
        sessions[sessionCount] = AuthSession({
            client: msg.sender,
            isAuthenticated: false,
            sessionStart: block.timestamp,
            innerAuthMethod: _innerAuthMethod
        });
        activeSessions[msg.sender] = sessionCount;

        emit TunnelEstablished(sessionCount, msg.sender, _innerAuthMethod);
        return sessionCount;
    }

    // Function to simulate inner authentication (e.g., PAP, MS-CHAPv2)
    function authenticate(uint256 _sessionId, string calldata _credentialHash) external {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        require(sessions[_sessionId].client == msg.sender, "Not your session");
        require(!sessions[_sessionId].isAuthenticated, "Already authenticated");

        // Simulate inner authentication (in real systems, verify credentials against a database)
        bool authSuccess = bytes(_credentialHash).length > 0; // Simplified check
        sessions[_sessionId].isAuthenticated = authSuccess;
        
        if (authSuccess) {
            // Keep session active
        } else {
            // Clear session on failure
            delete activeSessions[msg.sender];
            delete sessions[_sessionId];
        }

        emit AuthResult(_sessionId, msg.sender, authSuccess);
    }

    // Function to end a session
    function endSession(uint256 _sessionId) external {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        require(sessions[_sessionId].client == msg.sender || authorizedServers[msg.sender], "Unauthorized");
        
        delete activeSessions[sessions[_sessionId].client];
        delete sessions[_sessionId];
    }

    // Function to get session details
    function getSession(uint256 _sessionId) external view returns (address client, bool isAuthenticated, uint256 sessionStart, string memory innerAuthMethod) {
        require(_sessionId > 0 && _sessionId <= sessionCount, "Invalid session ID");
        AuthSession memory session = sessions[_sessionId];
        return (session.client, session.isAuthenticated, session.sessionStart, session.innerAuthMethod);
    }
}