// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Station Spoofing, Replay Command Attack, Protocol Drift Attack
/// Defense Types: Station Authentication, Message Freshness Enforcement, Command Whitelisting

contract OpenChargePointProtocol {
    address public admin;
    mapping(address => bool) public authorizedStations;
    mapping(bytes32 => bool) public usedMessages;
    mapping(address => uint256) public lastReportedCharge;

    event StationRegistered(address station);
    event ChargeReported(address station, uint256 amount);
    event UnauthorizedAttempt(address station);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    /// DEFENSE: Admin registers real charge stations
    function registerStation(address station) external onlyAdmin {
        authorizedStations[station] = true;
        emit StationRegistered(station);
    }

    /// ATTACK Simulation: fake station trying to send report
    function attackFakeStation(uint256 fakeChargeAmount) external {
        lastReportedCharge[msg.sender] = fakeChargeAmount;
        emit UnauthorizedAttempt(msg.sender);
    }

    /// DEFENSE: Station submits authenticated, fresh, verified message
    function reportCharge(uint256 _chargeAmount, uint256 _timestamp, bytes32 _messageHash, uint8 v, bytes32 r, bytes32 s) external {
        require(authorizedStations[msg.sender], "Station not authorized");

        // Message must be fresh and not replayed
        require(!usedMessages[_messageHash], "Replay detected");
        require(block.timestamp - _timestamp <= 300, "Message too old"); // Allow max 5 minutes drift

        // Verify the signature
        bytes32 expectedHash = keccak256(abi.encodePacked(msg.sender, _chargeAmount, _timestamp));
        require(_messageHash == expectedHash, "Hash mismatch");

        address signer = ecrecover(toEthSignedMessageHash(expectedHash), v, r, s);
        require(signer == msg.sender, "Invalid signature");

        // Mark the message as used
        usedMessages[_messageHash] = true;

        lastReportedCharge[msg.sender] = _chargeAmount;

        emit ChargeReported(msg.sender, _chargeAmount);
    }

    // Utility: mimic EIP-191 prefix ("\x19Ethereum Signed Message:\n32")
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // Admin can view last report
    function viewLastCharge(address station) external view returns (uint256) {
        return lastReportedCharge[station];
    }
}
