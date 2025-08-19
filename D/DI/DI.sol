// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DataIntegrityRegistry (fixed: renamed `sealed` -> `isSealed`)
 *
 * Ensures integrity:
 *  - At rest: versioned content hashes; optional Merkle roots
 *  - During processing: 2-phase begin/commit with input hash check
 *  - In transit: EIP-712 attested updates with nonce/deadline
 *
 * Minimal role system: ADMIN, WRITER, AUDITOR, SIGNER
 * No external imports (avoids ENOENT issues).
 */
contract DataIntegrityRegistry {
    // ----------------------------- Roles -----------------------------
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant WRITER_ROLE        = keccak256("WRITER_ROLE");
    bytes32 public constant AUDITOR_ROLE       = keccak256("AUDITOR_ROLE");
    bytes32 public constant SIGNER_ROLE        = keccak256("SIGNER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access: missing role");
        _;
    }

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }

    // ----------------------------- Records --------------------------
    struct Record {
        // Integrity at rest
        bytes32 currentHash;     // hash of current content
        bytes32 previousHash;    // previous version hash
        uint256 version;         // starts at 1
        address owner;           // optional owner
        bool    isSealed;        // once true, no further updates

        // Optional batch integrity
        bytes32 merkleRoot;      // root committing to a set of leaves

        // Processing guard
        bool    processing;          // true during processing session
        bytes32 expectedInputHash;   // must equal currentHash at begin
    }

    mapping(bytes32 => Record) public records;

    // -------------------------- EIP-712 (Transit) --------------------
    string public constant NAME    = "DataIntegrityRegistry";
    string public constant VERSION = "1";

    bytes32 public immutable DOMAIN_SEPARATOR;

    // struct IntegrityAttestation { bytes32 recordId; bytes32 newHash; uint256 nonce; uint256 deadline; }
    bytes32 public constant INTEGRITY_ATTEST_TYPEHASH =
        keccak256("IntegrityAttestation(bytes32 recordId,bytes32 newHash,uint256 nonce,uint256 deadline)");

    mapping(address => uint256) public nonces; // per-signer replay protection

    // ----------------------------- Events ---------------------------
    event RecordCreated(bytes32 indexed recordId, address indexed owner, bytes32 hash, string uri);
    event RecordUpdated(bytes32 indexed recordId, uint256 version, bytes32 oldHash, bytes32 newHash, string uri);
    event RecordSealed(bytes32 indexed recordId, uint256 version, bytes32 finalHash);
    event MerkleRootSet(bytes32 indexed recordId, bytes32 merkleRoot);

    event ProcessingBegan(bytes32 indexed recordId, bytes32 expectedInputHash);
    event ProcessingCommitted(bytes32 indexed recordId, bytes32 outputHash, uint256 version);

    event AttestedTransit(bytes32 indexed recordId, address indexed signer, bytes32 newHash, uint256 nonce, uint256 deadline);

    // --------------------------- Constructor ------------------------
    constructor(address admin) {
        require(admin != address(0), "admin=0");

        _roles[DEFAULT_ADMIN_ROLE][admin] = true;
        emit RoleGranted(DEFAULT_ADMIN_ROLE, admin, msg.sender);

        _roles[WRITER_ROLE][admin]  = true;
        _roles[AUDITOR_ROLE][admin] = true;
        _roles[SIGNER_ROLE][admin]  = true;
        emit RoleGranted(WRITER_ROLE, admin, msg.sender);
        emit RoleGranted(AUDITOR_ROLE, admin, msg.sender);
        emit RoleGranted(SIGNER_ROLE, admin, msg.sender);

        uint256 chainId;
        assembly { chainId := chainid() }
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            chainId,
            address(this)
        ));
    }

    // ----------------------------- Helpers --------------------------
    function computeHash(bytes memory data) external pure returns (bytes32) {
        return keccak256(data);
    }

    function verifyMerkle(bytes32 recordId, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        bytes32 root = records[recordId].merkleRoot;
        require(root != bytes32(0), "no root");
        return _verifyMerkle(leaf, proof, root);
    }

    // ---------------------- Storage Integrity -----------------------
    function createRecord(bytes32 recordId, address owner, bytes32 initialHash, string calldata uri)
        external
        onlyRole(WRITER_ROLE)
    {
        require(recordId != bytes32(0), "id=0");
        Record storage r = records[recordId];
        require(r.owner == address(0), "exists");

        r.currentHash = initialHash;
        r.previousHash = bytes32(0);
        r.version = 1;
        r.owner = owner;

        emit RecordCreated(recordId, owner, initialHash, uri);
    }

    function updateRecord(bytes32 recordId, bytes32 newHash, string calldata uri)
        external
        onlyRole(WRITER_ROLE)
    {
        _updateRecord(recordId, newHash, uri);
    }

    function sealRecord(bytes32 recordId) external onlyRole(AUDITOR_ROLE) {
        Record storage r = records[recordId];
        require(r.owner != address(0), "unknown");
        require(!r.isSealed, "sealed");
        r.isSealed = true;
        emit RecordSealed(recordId, r.version, r.currentHash);
    }

    function setMerkleRoot(bytes32 recordId, bytes32 root) external onlyRole(AUDITOR_ROLE) {
        Record storage r = records[recordId];
        require(r.owner != address(0), "unknown");
        require(!r.isSealed, "sealed");
        r.merkleRoot = root;
        emit MerkleRootSet(recordId, root);
    }

    function verifyData(bytes32 recordId, bytes calldata data) external view returns (bool) {
        Record storage r = records[recordId];
        require(r.owner != address(0), "unknown");
        return keccak256(data) == r.currentHash;
    }

    // -------------------- Processing Integrity ----------------------
    function beginProcessing(bytes32 recordId, bytes32 expectedInputHash)
        external
        onlyRole(WRITER_ROLE)
    {
        Record storage r = records[recordId];
        require(r.owner != address(0), "unknown");
        require(!r.isSealed, "sealed");
        require(!r.processing, "already processing");
        require(expectedInputHash == r.currentHash, "input!=current");

        r.processing = true;
        r.expectedInputHash = expectedInputHash;

        emit ProcessingBegan(recordId, expectedInputHash);
    }

    function commitProcessing(bytes32 recordId, bytes32 outputHash, string calldata uri)
        external
        onlyRole(WRITER_ROLE)
    {
        Record storage r = records[recordId];
        require(r.processing, "not processing");
        r.processing = false;
        r.expectedInputHash = bytes32(0);

        _updateRecord(recordId, outputHash, uri);
        emit ProcessingCommitted(recordId, outputHash, records[recordId].version);
    }

    // ------------------- Transit Integrity (EIP-712) ----------------
    function acceptAttestedUpdate(
        bytes32 recordId,
        bytes32 newHash,
        uint256 nonce,
        uint256 deadline,
        uint8   v, bytes32 r, bytes32 s,
        string calldata uri
    ) external onlyRole(WRITER_ROLE)
    {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = _buildDigest(keccak256(abi.encode(
            INTEGRITY_ATTEST_TYPEHASH,
            recordId,
            newHash,
            nonce,
            deadline
        )));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        require(_roles[SIGNER_ROLE][signer], "signer !auth");

        require(nonces[signer] == nonce, "bad nonce");
        nonces[signer] = nonce + 1;

        emit AttestedTransit(recordId, signer, newHash, nonce, deadline);

        _updateRecord(recordId, newHash, uri);
    }

    // ------------------------- Internal Utils -----------------------
    function _updateRecord(bytes32 recordId, bytes32 newHash, string calldata uri) internal {
        Record storage r = records[recordId];
        require(r.owner != address(0), "unknown");
        require(!r.isSealed, "sealed");

        bytes32 old = r.currentHash;
        r.previousHash = old;
        r.currentHash = newHash;
        r.version += 1;

        emit RecordUpdated(recordId, r.version, old, newHash, uri);
    }

    function _verifyMerkle(bytes32 leaf, bytes32[] calldata proof, bytes32 root) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (computed <= p) {
                computed = keccak256(abi.encodePacked(computed, p));
            } else {
                computed = keccak256(abi.encodePacked(p, computed));
            }
        }
        return computed == root;
    }

    function _buildDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}
