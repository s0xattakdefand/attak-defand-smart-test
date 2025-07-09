// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATABASE OF GENOTYPES AND PHENOTYPES DEMO
 * — “A database of genotypes and phenotypes.”
 * Sources: NISTIR 7693
 *
 * SECTION 1 — VulnerableGenotypePhenotypeDB
 *   • Anyone may add or read raw genotype/phenotype strings.
 *
 * SECTION 2 — SecureGenotypePhenotypeRegistry
 *   • RESEARCHERs submit only hash pointers.
 *   • VIEWERs may read metadata.
 *   • RBAC enforcement and audit events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableGenotypePhenotypeDB
/// -------------------------------------------------------------------------
contract VulnerableGenotypePhenotypeDB {
    struct Entry {
        string genotype;
        string phenotype;
    }

    mapping(uint256 => Entry) public entries;
    uint256 public nextId;

    event EntryAdded(uint256 indexed id, string genotype, string phenotype, address indexed by);

    /// Anyone can add raw genotype/phenotype data
    function addEntry(string calldata genotype, string calldata phenotype) external {
        uint256 id = nextId++;
        entries[id] = Entry(genotype, phenotype);
        emit EntryAdded(id, genotype, phenotype, msg.sender);
    }

    /// Anyone can read any entry
    function getEntry(uint256 id) external view returns (string memory genotype, string memory phenotype) {
        Entry storage e = entries[id];
        return (e.genotype, e.phenotype);
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — Helpers: Ownable & RBAC
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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

abstract contract RBAC is Ownable {
    bytes32 public constant RESEARCHER = keccak256("RESEARCHER");
    bytes32 public constant VIEWER     = keccak256("VIEWER");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(RESEARCHER, msg.sender);
        _grantRole(VIEWER, msg.sender);
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
/// SECTION 3 — SecureGenotypePhenotypeRegistry
/// -------------------------------------------------------------------------
contract SecureGenotypePhenotypeRegistry is RBAC {
    struct EntryMeta {
        bytes32 genotypeHash;   // e.g. keccak256 of encrypted genotype blob
        bytes32 phenotypeHash;  // e.g. keccak256 of encrypted phenotype blob
        address uploader;
        uint256 timestamp;
    }

    mapping(uint256 => EntryMeta) private _entries;
    uint256 public nextId;

    event EntryStored(
        uint256 indexed id,
        address indexed uploader,
        bytes32 genotypeHash,
        bytes32 phenotypeHash,
        uint256 timestamp
    );

    /// Researchers submit only pointers (hashes) to off-chain encrypted data
    function addEntry(bytes32 genotypeHash, bytes32 phenotypeHash)
        external
        onlyRole(RESEARCHER)
        returns (uint256 id)
    {
        id = nextId++;
        _entries[id] = EntryMeta({
            genotypeHash: genotypeHash,
            phenotypeHash: phenotypeHash,
            uploader: msg.sender,
            timestamp: block.timestamp
        });
        emit EntryStored(id, msg.sender, genotypeHash, phenotypeHash, block.timestamp);
    }

    /// Viewers retrieve metadata, not raw data
    function getEntryMeta(uint256 id)
        external
        view
        onlyRole(VIEWER)
        returns (
            bytes32 genotypeHash,
            bytes32 phenotypeHash,
            address uploader,
            uint256 timestamp
        )
    {
        EntryMeta storage e = _entries[id];
        return (e.genotypeHash, e.phenotypeHash, e.uploader, e.timestamp);
    }
}
