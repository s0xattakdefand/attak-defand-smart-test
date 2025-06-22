// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Spoofing, Replay, Unauthorized Command
/// Defense Types: Signature Check, DAO Role Auth, Nonce Binding

contract AviationCyberInitiative {
    address public daoControl;
    mapping(address => bool) public certifiedOperators;
    mapping(bytes32 => bool) public usedTelemetryHashes;

    event TelemetryReceived(address drone, uint256 altitude, uint256 speed, bytes32 hash);
    event FlightCommandIssued(address drone, string command);
    event AttackDetected(address attacker, string reason);

    constructor(address _daoControl) {
        daoControl = _daoControl;
    }

    modifier onlyDAO() {
        require(msg.sender == daoControl, "Not DAO control");
        _;
    }

    modifier onlyOperator() {
        require(certifiedOperators[msg.sender], "Not certified operator");
        _;
    }

    /// DEFENSE: DAO certifies drone ops
    function certifyOperator(address op) external onlyDAO {
        certifiedOperators[op] = true;
    }

    /// DEFENSE: Submit telemetry with signature (EIP-191)
    function submitTelemetry(
        address drone,
        uint256 altitude,
        uint256 speed,
        bytes calldata signature
    ) external {
        bytes32 payload = keccak256(abi.encodePacked(drone, altitude, speed, block.timestamp / 60)); // round timestamp
        bytes32 signedMsg = ECDSA.toEthSignedMessageHash(payload);
        address signer = ECDSA.recover(signedMsg, signature);

        require(certifiedOperators[signer], "Not a certified telemetry source");
        require(!usedTelemetryHashes[payload], "Replay detected");

        usedTelemetryHashes[payload] = true;
        emit TelemetryReceived(drone, altitude, speed, payload);
    }

    /// DEFENSE: Issue command (DAO only)
    function issueCommand(address drone, string calldata command) external onlyDAO {
        emit FlightCommandIssued(drone, command);
    }

    /// ATTACK: Spoof telemetry or send unapproved command
    function attackSpoofTelemetry(address drone, uint256 alt, uint256 speed) external {
        emit AttackDetected(msg.sender, "Telemetry spoof attempt");
        revert("Blocked spoof");
    }

    function attackIssueCommand(string calldata cmd) external {
        emit AttackDetected(msg.sender, "Unauthorized flight command");
        revert("Blocked unauthorized command");
    }
}

/// ECDSA lib
library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}
