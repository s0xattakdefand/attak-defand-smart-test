// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
  DATA PROVENANCE / CHAIN OF CUSTODY DEMO
  CNSSI‐4009‐2015 (adapted)  —  “method of generation, transmission and storage
  of information that may be used to trace the origin of a piece of information”
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableEvidenceStore
   ⚠️ Stores evidence blobs without any provenance tracking or access control.
----------------------------------------------------------------------------*/
contract VulnerableEvidenceStore {
    struct Evidence {
        bytes    data;
        address  uploader;
        uint256  timestamp;
    }

    mapping(uint256 => Evidence) public evidences;
    uint256 public counter;

    /// Anyone can upload arbitrary “evidence” with no audit trail.
    function uploadEvidence(bytes calldata blob) external {
        evidences[counter] = Evidence(blob, msg.sender, block.timestamp);
        counter++;
    }

    /// Anyone can read any evidence at any time.
    function getEvidence(uint256 id) external view returns (bytes memory, address, uint256) {
        Evidence storage e = evidences[id];
        return (e.data, e.uploader, e.timestamp);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — MiniRoles + MiniECDSA (helpers for hardened tracker)
----------------------------------------------------------------------------*/
abstract contract MiniRoles {
    bytes32 public constant ADMIN      = keccak256("ADMIN");
    bytes32 public constant CUSTODIAN  = keccak256("CUSTODIAN");

    mapping(bytes32 => mapping(address => bool)) internal _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied");
        _;
    }

    constructor() {
        _grant(ADMIN, msg.sender);
    }

    function grantRole(bytes32 role, address acct) external onlyRole(ADMIN) {
        _grant(role, acct);
    }
    function revokeRole(bytes32 role, address acct) external onlyRole(ADMIN) {
        _revoke(role, acct);
    }
    function hasRole(bytes32 role, address acct) public view returns(bool) {
        return _roles[role][acct];
    }

    function _grant(bytes32 role, address acct) internal {
        if (!_roles[role][acct]) {
            _roles[role][acct] = true;
            emit RoleGranted(role, acct);
        }
    }
    function _revoke(bytes32 role, address acct) internal {
        if (_roles[role][acct]) {
            _roles[role][acct] = false;
            emit RoleRevoked(role, acct);
        }
    }
}

library MiniECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(hash), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — ChainOfCustodyTracker (✅ hardened)
   • Enforces roles: only CUSTODIANs may manage custody.
   • Records every hand-off with actor, timestamp, action, and evidenceHash.
   • Prevents unauthorized transfers and provides full on-chain audit.
----------------------------------------------------------------------------*/
contract ChainOfCustodyTracker is MiniRoles {
    using MiniECDSA for bytes32;

    struct Entry {
        address actor;
        bytes32 evidenceHash;
        string  action;       // e.g. "collected","transferred"
        uint256 timestamp;
    }

    // Evidence metadata
    struct EvidenceMeta {
        bytes32 evidenceHash;  // keccak256 of blob stored off-chain
        address currentCustodian;
        bool    exists;
    }

    // evidenceId ⇒ metadata
    mapping(uint256 => EvidenceMeta) public metadata;
    // evidenceId ⇒ ordered list of custody entries
    mapping(uint256 => Entry[]) public custodyLog;
    uint256 public nextEvidenceId;

    event EvidenceRegistered(uint256 indexed id, bytes32 hash, address indexed custodian);
    event CustodyTransferred(uint256 indexed id, address indexed from, address indexed to);

    /// ADMIN registers new evidence (e.g., at seizure), setting initial custodian.
    function registerEvidence(bytes32 evidenceHash, address initialCustodian)
        external
        onlyRole(ADMIN)
        returns (uint256 id)
    {
        id = nextEvidenceId++;
        metadata[id] = EvidenceMeta(evidenceHash, initialCustodian, true);
        custodyLog[id].push(Entry({
            actor: initialCustodian,
            evidenceHash: evidenceHash,
            action: "registered",
            timestamp: block.timestamp
        }));
        _grant(CUSTODIAN, initialCustodian);
        emit EvidenceRegistered(id, evidenceHash, initialCustodian);
    }

    /// Current custodian transfers custody to `newCustodian`.
    function transferCustody(uint256 id, address newCustodian)
        external
        onlyRole(CUSTODIAN)
    {
        require(metadata[id].exists, "Unknown evidence");
        address from = metadata[id].currentCustodian;
        require(msg.sender == from, "Not current custodian");

        metadata[id].currentCustodian = newCustodian;
        custodyLog[id].push(Entry({
            actor: newCustodian,
            evidenceHash: metadata[id].evidenceHash,
            action: "transferred",
            timestamp: block.timestamp
        }));
        _grant(CUSTODIAN, newCustodian);
        emit CustodyTransferred(id, from, newCustodian);
    }

    /// View the full custody chain for an evidence item.
    function getCustodyLog(uint256 id)
        external
        view
        returns (Entry[] memory)
    {
        return custodyLog[id];
    }
}
