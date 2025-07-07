// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATA ACCEPTANCE TESTING DEMO
   NIST SP 800-55v1 / NIST SP 800-152
   “The process of determining that data or a process for collecting data
    is acceptable according to a predefined set of tests and the results
    of those tests.”
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDataCollector (⚠️ no acceptance testing)
   • Anyone may submit any data; no tests are run.
   • All data is treated as valid.
----------------------------------------------------------------------------*/
contract VulnerableDataCollector {
    struct Record {
        uint256 id;
        string payload;
        address submitter;
        uint256 timestamp;
    }

    mapping(uint256 => Record) public records;
    uint256 public nextId;

    event DataSubmitted(uint256 indexed id, address indexed submitter, string payload);

    /// Submit data without any validation
    function submitData(string calldata payload) external {
        uint256 id = nextId++;
        records[id] = Record(id, payload, msg.sender, block.timestamp);
        emit DataSubmitted(id, msg.sender, payload);
    }

    /// Retrieve any record
    function getRecord(uint256 id) external view returns (Record memory) {
        return records[id];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Minimal RBAC for validators
----------------------------------------------------------------------------*/
abstract contract RBAC {
    bytes32 public constant ADMIN     = keccak256("ADMIN");
    bytes32 public constant VALIDATOR = keccak256("VALIDATOR");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
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

    function hasRole(bytes32 role, address acct) public view returns (bool) {
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

/*----------------------------------------------------------------------------
   SECTION 3 — DataAcceptance (✅ acceptance testing & approval)
----------------------------------------------------------------------------*/
contract DataAcceptance is RBAC {
    struct Proposed {
        string payload;
        address submitter;
        uint256   timestamp;
        bool      exists;
    }

    struct Approved {
        string payload;
        address submitter;
        uint256   timestamp;
        address   validator;
        uint256   validatedAt;
    }

    // proposalId ⇒ Proposed
    mapping(uint256 => Proposed) public proposals;
    uint256 public nextProposalId;

    // proposalId ⇒ Approved
    mapping(uint256 => Approved) public approvedRecords;

    event ProposalCreated(uint256 indexed pid, address indexed submitter, string payload);
    event ProposalApproved(uint256 indexed pid, address indexed validator);
    event ProposalRejected(uint256 indexed pid, address indexed validator, string reason);

    /// Anyone may propose data for acceptance testing
    function propose(string calldata payload) external {
        uint256 pid = nextProposalId++;
        proposals[pid] = Proposed({
            payload: payload,
            submitter: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });
        emit ProposalCreated(pid, msg.sender, payload);
    }

    /// Validator runs predefined tests and approves if they pass
    function approve(uint256 pid) external onlyRole(VALIDATOR) {
        Proposed storage p = proposals[pid];
        require(p.exists, "No such proposal");
        // Example tests:
        bytes memory b = bytes(p.payload);
        require(b.length > 0, "Payload empty");
        require(b.length <= 256, "Payload too long");
        // First character must be a letter
        bytes1 first = b[0];
        bool isLetter = (first >= 0x41 && first <= 0x5A) || (first >= 0x61 && first <= 0x7A);
        require(isLetter, "Must start with letter");

        // All tests passed → record as approved
        approvedRecords[pid] = Approved({
            payload: p.payload,
            submitter: p.submitter,
            timestamp: p.timestamp,
            validator: msg.sender,
            validatedAt: block.timestamp
        });
        delete proposals[pid];
        emit ProposalApproved(pid, msg.sender);
    }

    /// Validator may reject proposal with reason
    function reject(uint256 pid, string calldata reason) external onlyRole(VALIDATOR) {
        Proposed storage p = proposals[pid];
        require(p.exists, "No such proposal");
        delete proposals[pid];
        emit ProposalRejected(pid, msg.sender, reason);
    }

    /// Fetch an approved record
    function getApproved(uint256 pid) external view returns (Approved memory) {
        return approvedRecords[pid];
    }
}
