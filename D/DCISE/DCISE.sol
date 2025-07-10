// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DoD–Defense Industrial Base Collaborative Information Sharing Environment (CISE)
 * — Facilitates secure sharing of threat and vulnerability information
 *   between the DoD and Defense Industrial Base participants.
 *
 * SECTION 1 — Ownable & RBAC helpers
 */
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
    bytes32 public constant CISE_ADMIN    = keccak256("CISE_ADMIN");
    bytes32 public constant PARTICIPANT   = keccak256("PARTICIPANT");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(CISE_ADMIN, msg.sender);
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

/*
 * SECTION 2 — CISE Environment
 */
contract CISE is RBAC {
    enum Classification { UNCLASSIFIED, SENSITIVE, SECRET, TOP_SECRET }

    struct Info {
        Classification classification;
        bytes32       dataHash;     // keccak256 of off‐chain payload
        address       publisher;
        uint256       timestamp;
    }

    uint256 public nextInfoId;
    mapping(uint256 => Info) private _infos;

    // track registered participants
    mapping(address => bool) public participants;

    // Events
    event ParticipantRegistered(address indexed participant);
    event ParticipantUnregistered(address indexed participant);
    event InfoShared(
        uint256 indexed infoId,
        Classification classification,
        address indexed publisher,
        bytes32 dataHash,
        uint256 timestamp
    );

    /// @notice CISE_ADMIN registers a participant (Defense Industrial Base member)
    function registerParticipant(address participant) external onlyRole(CISE_ADMIN) {
        require(!participants[participant], "Already registered");
        participants[participant] = true;
        _grantRole(PARTICIPANT, participant);
        emit ParticipantRegistered(participant);
    }

    /// @notice CISE_ADMIN revokes a participant
    function unregisterParticipant(address participant) external onlyRole(CISE_ADMIN) {
        require(participants[participant], "Not registered");
        participants[participant] = false;
        _revokeRole(PARTICIPANT, participant);
        emit ParticipantUnregistered(participant);
    }

    /// @notice Share new information with a classification level
    function shareInfo(Classification classification, bytes32 dataHash)
        external
        onlyRole(PARTICIPANT)
    {
        require(classification <= Classification.TOP_SECRET, "Invalid classification");
        uint256 id = nextInfoId++;
        _infos[id] = Info({
            classification: classification,
            dataHash:       dataHash,
            publisher:      msg.sender,
            timestamp:      block.timestamp
        });
        emit InfoShared(id, classification, msg.sender, dataHash, block.timestamp);
    }

    /// @notice Retrieve metadata for a shared info record
    function getInfo(uint256 infoId)
        external
        view
        returns (
            Classification classification,
            bytes32       dataHash,
            address       publisher,
            uint256       timestamp
        )
    {
        Info storage info = _infos[infoId];
        require(info.timestamp != 0, "Unknown infoId");
        // only participants or CISE_ADMIN can view
        require(
            hasRole(PARTICIPANT, msg.sender) || hasRole(CISE_ADMIN, msg.sender),
            "Access denied"
        );
        return (info.classification, info.dataHash, info.publisher, info.timestamp);
    }
}
