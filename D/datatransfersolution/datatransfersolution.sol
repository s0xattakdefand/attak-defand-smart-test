// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * CROSS-DOMAIN CONNECTOR DEMO
 * CNSSI-4009-2015 / DoDI 8540.01
 * 
 * Demonstrates:
 *  1) VulnerableDomainConnector — naive forwarding between security domains
 *  2) SecureCrossDomainGateway  — enforces origin domain checks, approvals,
 *                                 message integrity, and audit logging
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDomainConnector (⚠️ insecure)
----------------------------------------------------------------------------*/
contract VulnerableDomainConnector {
    // Message as raw bytes, with claimed origin domain ID
    struct Message {
        uint16 originDomain;
        bytes payload;
    }

    Message[] public inbox;

    event MessageForwarded(uint16 indexed originDomain, bytes payload);

    /// Any caller can submit a message claiming any origin domain.
    function submitMessage(uint16 originDomain, bytes calldata payload) external {
        inbox.push(Message(originDomain, payload));
        emit MessageForwarded(originDomain, payload);
    }

    /// Retrieve messages
    function getMessage(uint256 idx) external view returns (uint16, bytes memory) {
        Message storage m = inbox[idx];
        return (m.originDomain, m.payload);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers for SecureCrossDomainGateway
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: not owner");
        _;
    }
    function owner() public view returns (address) {
        return _owner;
    }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/// Minimal ECDSA helper
library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0, calldataload(add(sig.offset,64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureCrossDomainGateway (✅ hardened)
----------------------------------------------------------------------------*/
contract SecureCrossDomainGateway is Ownable {
    using ECDSA for bytes32;

    // Approved domain pairs: origin→destination→enabled
    mapping(uint16 => mapping(uint16 => bool)) public approvedPair;

    // Relayer addresses allowed to forward messages
    mapping(address => bool) public approvedRelayer;

    struct Message {
        uint16 originDomain;
        uint16 destDomain;
        bytes payload;
        address relayer;
        uint256 timestamp;
    }

    Message[] public log;

    event DomainPairApproved(uint16 indexed origin, uint16 indexed dest);
    event RelayerApproved(address indexed relayer);
    event MessageForwarded(
        uint16 indexed originDomain,
        uint16 indexed destDomain,
        address indexed relayer,
        bytes payload
    );

    /// Owner enables a domain-to-domain flow
    function approveDomainPair(uint16 origin, uint16 dest) external onlyOwner {
        approvedPair[origin][dest] = true;
        emit DomainPairApproved(origin, dest);
    }

    /// Owner approves a relayer
    function approveRelayer(address relayer) external onlyOwner {
        approvedRelayer[relayer] = true;
        emit RelayerApproved(relayer);
    }

    /**
     * @notice Forward a cross-domain message.
     * @param originDomain  The numeric ID of origin domain.
     * @param destDomain    The numeric ID of destination domain.
     * @param payload       The opaque message payload.
     * @param ownerSig      Owner’s signature over (origin, dest, payload hash).
     */
    function forwardMessage(
        uint16 originDomain,
        uint16 destDomain,
        bytes calldata payload,
        bytes calldata ownerSig
    ) external {
        require(approvedRelayer[msg.sender], "Relay: not authorized");
        require(approvedPair[originDomain][destDomain], "Flow not approved");

        // Verify owner signed off-chain on this specific message
        bytes32 msgHash = keccak256(abi.encodePacked(address(this), originDomain, destDomain, keccak256(payload)));
        require(msgHash.recover(ownerSig) == owner(), "Invalid owner signature");

        log.push(Message(originDomain, destDomain, payload, msg.sender, block.timestamp));
        emit MessageForwarded(originDomain, destDomain, msg.sender, payload);
    }

    /// Retrieve a logged message
    function getLogEntry(uint256 idx) external view returns (
        uint16 originDomain,
        uint16 destDomain,
        bytes memory payload,
        address relayer,
        uint256 timestamp
    ) {
        Message storage m = log[idx];
        return (m.originDomain, m.destDomain, m.payload, m.relayer, m.timestamp);
    }
}
