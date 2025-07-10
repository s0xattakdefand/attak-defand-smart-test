// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DEFENSE CONTRACT MANAGEMENT AGENCY (DCMA) DEMO
 * — Provides on‐chain management of defense contracts with:
 *    • Role‐based access for ADMIN, MANAGER, and AUDITOR
 *    • Creation, modification, approval, and audit‐logging of contracts
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }
    function owner() public view returns (address) {
        return _owner;
    }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant DCMA_ADMIN   = keccak256("DCMA_ADMIN");
    bytes32 public constant CONTRACT_MGR = keccak256("CONTRACT_MGR");
    bytes32 public constant AUDITOR      = keccak256("AUDITOR");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(DCMA_ADMIN, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }
    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }
    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DCMA Contract Registry
/// -------------------------------------------------------------------------
contract DefenseContractManagementAgency is RBAC {
    enum Status { DRAFT, SUBMITTED, APPROVED, REJECTED, COMPLETED }

    struct ContractRecord {
        uint256    id;
        string     title;
        string     details;     // off‐chain details pointer (e.g. IPFS hash)
        address    creator;     // must be CONTRACT_MGR
        uint256    createdAt;
        Status     status;
        address    reviewer;    // who approved/rejected
        uint256    reviewedAt;
    }

    uint256 public nextContractId;
    mapping(uint256 => ContractRecord) private _contracts;

    event ContractCreated(
        uint256 indexed id,
        string title,
        address indexed creator,
        uint256 timestamp
    );
    event ContractSubmitted(
        uint256 indexed id,
        address indexed submitter,
        uint256 timestamp
    );
    event ContractReviewed(
        uint256 indexed id,
        Status status,
        address indexed reviewer,
        uint256 timestamp
    );
    event ContractCompleted(
        uint256 indexed id,
        address indexed by,
        uint256 timestamp
    );

    /// @notice CONTRACT_MGR creates a new contract record in DRAFT
    function createContract(string calldata title, string calldata details)
        external
        onlyRole(CONTRACT_MGR)
        returns (uint256 id)
    {
        id = nextContractId++;
        _contracts[id] = ContractRecord({
            id:        id,
            title:     title,
            details:   details,
            creator:   msg.sender,
            createdAt: block.timestamp,
            status:    Status.DRAFT,
            reviewer:  address(0),
            reviewedAt: 0
        });
        emit ContractCreated(id, title, msg.sender, block.timestamp);
    }

    /// @notice CONTRACT_MGR submits a DRAFT for review
    function submitContract(uint256 id) external onlyRole(CONTRACT_MGR) {
        ContractRecord storage c = _contracts[id];
        require(c.creator == msg.sender, "Not creator");
        require(c.status == Status.DRAFT, "Must be DRAFT");
        c.status = Status.SUBMITTED;
        emit ContractSubmitted(id, msg.sender, block.timestamp);
    }

    /// @notice DCMA_ADMIN reviews a submitted contract
    function reviewContract(uint256 id, bool approve) external onlyRole(DCMA_ADMIN) {
        ContractRecord storage c = _contracts[id];
        require(c.status == Status.SUBMITTED, "Must be SUBMITTED");
        c.status = approve ? Status.APPROVED : Status.REJECTED;
        c.reviewer = msg.sender;
        c.reviewedAt = block.timestamp;
        emit ContractReviewed(id, c.status, msg.sender, block.timestamp);
    }

    /// @notice CONTRACT_MGR marks an APPROVED contract as COMPLETED
    function completeContract(uint256 id) external onlyRole(CONTRACT_MGR) {
        ContractRecord storage c = _contracts[id];
        require(c.status == Status.APPROVED, "Must be APPROVED");
        c.status = Status.COMPLETED;
        emit ContractCompleted(id, msg.sender, block.timestamp);
    }

    /// @notice AUDITOR views contract details and status (read-only)
    function viewContract(uint256 id)
        external
        view
        onlyRole(AUDITOR)
        returns (
            string memory title,
            string memory details,
            address creator,
            uint256 createdAt,
            Status status,
            address reviewer,
            uint256 reviewedAt
        )
    {
        ContractRecord storage c = _contracts[id];
        return (
            c.title, c.details, c.creator, c.createdAt,
            c.status, c.reviewer, c.reviewedAt
        );
    }
}
