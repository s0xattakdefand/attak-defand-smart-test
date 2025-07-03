// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataInTransitRegistry
 * @notice
 *   Implements “Data in Transit” tracking per CNSSI/NIST guidance:
 *   • ADMIN_ROLE manages participants and may pause the registry.
 *   • SENDER_ROLE and RECEIVER_ROLE mark who may send or receive data.
 *   • Each transmission is logged as an event with immutable metadata.
 *
 * Concepts:
 *   – Data is assumed encrypted off-chain; on-chain we log a content hash or pointer.
 *   – Logging ensures non-repudiation and auditability of in-transit data.
 */
contract DataInTransitRegistry is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE     = keccak256("ADMIN_ROLE");
    bytes32 public constant SENDER_ROLE    = keccak256("SENDER_ROLE");
    bytes32 public constant RECEIVER_ROLE  = keccak256("RECEIVER_ROLE");

    struct Transmission {
        address sender;
        address receiver;
        bytes32 contentHash; // e.g., hash of encrypted payload
        string  pointer;     // off-chain pointer (IPFS, HTTPS URL)
        uint256 timestamp;
    }

    // auto-incrementing transmission ID
    uint256 private _nextId = 1;
    // stored transmissions (optional on-chain storage)
    mapping(uint256 => Transmission) private _transmissions;

    event TransmissionLogged(
        uint256 indexed id,
        address indexed sender,
        address indexed receiver,
        bytes32 contentHash,
        string pointer,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "DIT: not admin");
        _;
    }

    modifier onlySender() {
        require(hasRole(SENDER_ROLE, msg.sender), "DIT: not sender");
        _;
    }

    modifier onlyReceiver(address receiver) {
        require(hasRole(RECEIVER_ROLE, receiver), "DIT: invalid receiver");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Grant SENDER_ROLE to an account
    function addSender(address acct) external onlyRole(ADMIN_ROLE) {
        grantRole(SENDER_ROLE, acct);
    }

    /// @notice Revoke SENDER_ROLE from an account
    function removeSender(address acct) external onlyRole(ADMIN_ROLE) {
        revokeRole(SENDER_ROLE, acct);
    }

    /// @notice Grant RECEIVER_ROLE to an account
    function addReceiver(address acct) external onlyRole(ADMIN_ROLE) {
        grantRole(RECEIVER_ROLE, acct);
    }

    /// @notice Revoke RECEIVER_ROLE from an account
    function removeReceiver(address acct) external onlyRole(ADMIN_ROLE) {
        revokeRole(RECEIVER_ROLE, acct);
    }

    /// @notice Pause the registry (prevent new transmissions)
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the registry
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Log a data transmission from `msg.sender` to `receiver`.
     * @param receiver     Destination address (must have RECEIVER_ROLE).
     * @param contentHash  Hash of the encrypted payload.
     * @param pointer      Off-chain pointer (e.g., IPFS hash or URL).
     * @return id          Unique transmission ID.
     */
    function logTransmission(
        address receiver,
        bytes32 contentHash,
        string calldata pointer
    )
        external
        whenNotPaused
        onlySender
        returns (uint256 id)
    {
        require(hasRole(RECEIVER_ROLE, receiver), "DIT: receiver not authorized");
        id = _nextId++;
        _transmissions[id] = Transmission({
            sender:      msg.sender,
            receiver:    receiver,
            contentHash: contentHash,
            pointer:     pointer,
            timestamp:   block.timestamp
        });
        emit TransmissionLogged(id, msg.sender, receiver, contentHash, pointer, block.timestamp);
    }

    /**
     * @notice Retrieve details of a logged transmission.
     * @param id Transmission ID.
     * @return sender      Sender address.
     * @return receiver    Receiver address.
     * @return contentHash Hash of the payload.
     * @return pointer     Off-chain pointer.
     * @return timestamp   When it was logged.
     */
    function getTransmission(uint256 id)
        external
        view
        returns (
            address sender,
            address receiver,
            bytes32 contentHash,
            string memory pointer,
            uint256 timestamp
        )
    {
        Transmission storage t = _transmissions[id];
        require(t.timestamp != 0, "DIT: not found");
        return (t.sender, t.receiver, t.contentHash, t.pointer, t.timestamp);
    }
}
