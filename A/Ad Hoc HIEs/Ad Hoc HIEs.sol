// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Ad Hoc HIE: Health Info Exchange with session-based access
contract AdHocHIE {
    address public admin;

    struct Session {
        address requester;
        address provider;
        bytes32 dataHash; // Hash of IPFS data or zkStruct
        uint256 expiresAt;
        bool approved;
    }

    uint256 public sessionIdCounter;
    mapping(uint256 => Session) public sessions;

    event SessionRequested(uint256 sessionId, address requester, address provider);
    event SessionApproved(uint256 sessionId);
    event DataAccessed(uint256 sessionId, bytes32 dataHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function requestSession(address provider, bytes32 dataHash, uint256 ttl) external returns (uint256 sessionId) {
        sessionId = ++sessionIdCounter;
        sessions[sessionId] = Session({
            requester: msg.sender,
            provider: provider,
            dataHash: dataHash,
            expiresAt: block.timestamp + ttl,
            approved: false
        });

        emit SessionRequested(sessionId, msg.sender, provider);
    }

    function approveSession(uint256 sessionId) external {
        Session storage s = sessions[sessionId];
        require(msg.sender == s.provider, "Not provider");
        require(!s.approved, "Already approved");

        s.approved = true;
        emit SessionApproved(sessionId);
    }

    function accessData(uint256 sessionId) external view returns (bytes32) {
        Session memory s = sessions[sessionId];
        require(msg.sender == s.requester, "Not requester");
        require(s.approved, "Not approved");
        require(block.timestamp <= s.expiresAt, "Session expired");

        // This hash maps to offchain encrypted content (IPFS, S3, ZK note)
        return s.dataHash;
    }
}
