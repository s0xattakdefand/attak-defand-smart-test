// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Unauthorized Data Access, Off-Chain Oracle Injection, Query Drift Attack
/// Defense Types: Access Control Enforcement, Trusted Oracle Validation, Query Consistency Check

contract OpenDatabaseConnectivity {
    address public admin;
    mapping(address => bool) public trustedOracles;
    uint256 public sensitiveData;
    mapping(bytes32 => bool) public usedRequests;

    event DataUpdated(address indexed updater, uint256 newData);
    event UnauthorizedDataRead(address indexed reader);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    // DEFENSE: Admin can set trusted oracles
    function setOracle(address oracle, bool trusted) external onlyAdmin {
        trustedOracles[oracle] = trusted;
    }

    /// ATTACK Simulation: Unauthorized reading or changing data
    function attackUnauthorizedDataAccess(uint256 fakeData) external {
        sensitiveData = fakeData;
        emit UnauthorizedDataRead(msg.sender);
    }

    /// DEFENSE: Proper off-chain data update with verification
    function updateDataFromOracle(
        uint256 newData,
        uint256 timestamp,
        uint256 nonce,
        bytes32 dataHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(trustedOracles[msg.sender], "Sender not trusted oracle");
        require(block.timestamp - timestamp <= 300, "Stale oracle data");

        // Prevent replay
        require(!usedRequests[dataHash], "Duplicate oracle update");

        // Verify the oracle signature
        bytes32 expectedHash = keccak256(abi.encodePacked(msg.sender, newData, timestamp, nonce));
        require(dataHash == expectedHash, "Hash mismatch");

        address signer = ecrecover(toEthSignedMessageHash(expectedHash), v, r, s);
        require(signer == msg.sender, "Invalid oracle signature");

        usedRequests[dataHash] = true;

        sensitiveData = newData;
        emit DataUpdated(msg.sender, newData);
    }

    // View sensitive data - DEFENSE: only admin
    function viewSensitiveData() external view returns (uint256) {
        require(msg.sender == admin, "Restricted view");
        return sensitiveData;
    }

    // Helper for Ethereum signed message prefix
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // Helper to generate expected hash off-chain
    function generateDataHash(
        address oracle,
        uint256 newData,
        uint256 timestamp,
        uint256 nonce
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(oracle, newData, timestamp, nonce));
    }
}
