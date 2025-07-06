// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*  ======================================================================
    CNSSI-1011  /  NIST SP 800-137   —   DATA LOSS PREVENTION DEMO
    ----------------------------------------------------------------------
       · Section 1 :  OpenBucket      (⚠️ vulnerable)
       · Section 2 :  Minimal RBAC
       · Section 3 :  SafeDLPVault    (✅ hardened)
    ====================================================================== */

/* ----------------------------------------------------------------------
   SECTION 1  —  VULNERABLE “OpenBucket”
   Stores cleartext, emits full payloads, anyone can read -- zero DLP.
   -------------------------------------------------------------------- */
contract OpenBucket {
    struct Blob {
        string title;
        string contents;           // ⚠️ proprietary data in clear text
        address owner;
        uint256 storedAt;
    }

    mapping(uint256 => Blob) public blobs; // public ⇒ data-at-rest exposed
    uint256 public counter;

    event BlobPushed(              // ⚠️ data-in-motion exposed in event log
        uint256 indexed id,
        string  title,
        string  contents,
        address indexed owner
    );

    function push(string calldata title, string calldata contents) external {
        blobs[counter] = Blob(title, contents, msg.sender, block.timestamp);
        emit BlobPushed(counter, title, contents, msg.sender); // leaked
        counter++;
    }

    /* Anyone can yank any blob (data-in-use completely unprotected) */
    function fetch(uint256 id) external view returns (Blob memory) {
        return blobs[id];
    }
}

/* ----------------------------------------------------------------------
   SECTION 2  —  MINIMAL ROLE-BASED ACCESS CONTROL (RBAC)
   Avoids external imports to keep file self-contained.
   -------------------------------------------------------------------- */
abstract contract RBAC {
    /* Roles */
    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant INGEST_ROLE   = keccak256("INGEST_ROLE");
    bytes32 public constant VIEW_ROLE     = keccak256("VIEW_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    constructor() {
        _grant(ADMIN_ROLE, msg.sender); // deployer is super-admin
    }

    /* Admins manage roles */
    function grant(bytes32 role, address acct) external onlyRole(ADMIN_ROLE) {
        _grant(role, acct);
    }
    function revoke(bytes32 role, address acct) external onlyRole(ADMIN_ROLE) {
        _revoke(role, acct);
    }
    function hasRole(bytes32 role, address acct) public view returns (bool) {
        return _roles[role][acct];
    }

    /* Internal helpers */
    function _grant(bytes32 r, address a) private {
        if (!_roles[r][a]) {
            _roles[r][a] = true;
            emit RoleGranted(r, a);
        }
    }
    function _revoke(bytes32 r, address a) private {
        if (_roles[r][a]) {
            _roles[r][a] = false;
            emit RoleRevoked(r, a);
        }
    }
}

/* ----------------------------------------------------------------------
   SECTION 3  —  HARDENED “SafeDLPVault”
   Implements centralised management, classification, and DLP controls.
   -------------------------------------------------------------------- */
contract SafeDLPVault is RBAC {
    /* Content classification per CNSSI / DoD style */
    enum Class { PUBLIC, CONFIDENTIAL, SECRET }

    struct DocMeta {
        Class   classLevel;      // data-at-rest label
        bytes32 hashPtr;         // keccak256 of blob (always required)
        string  title;           // non-sensitive descriptor
        address owner;           // uploader
        uint256 storedAt;
        bool    hasPlain;        // if true, plainBlob is stored
    }

    /* Storage */
    mapping(uint256 => DocMeta) private docs;
    mapping(uint256 => string)  private plainBlob; // only for PUBLIC
    uint256 public docCounter;

    /* Events (data-in-motion governed) */
    event DocumentRegistered(
        uint256 indexed id,
        Class   indexed classLevel,
        bytes32 indexed hashPtr,
        string  title,
        address owner
    );

    /* ---------------- INGEST (data-in-use) ----------------
       -  Only addresses with INGEST_ROLE may register content.
       -  For CONFIDENTIAL or SECRET the *plain* data must stay off-chain.
       ------------------------------------------------------ */
    function register(
        string calldata title,
        Class   classLevel,
        bytes   calldata clearOrCipherBlob          // may be "" for SECRET
    ) external onlyRole(INGEST_ROLE) returns (uint256 id) {
        require(
            classLevel == Class.PUBLIC ? clearOrCipherBlob.length > 0 : true,
            "PUBLIC requires cleartext"
        );

        bytes32 hp = keccak256(clearOrCipherBlob);
        id = docCounter++;

        docs[id] = DocMeta({
            classLevel : classLevel,
            hashPtr    : hp,
            title      : title,
            owner      : msg.sender,
            storedAt   : block.timestamp,
            hasPlain   : classLevel == Class.PUBLIC
        });

        if (classLevel == Class.PUBLIC) {
            /* Store plain only for PUBLIC -- data-at-rest policy */
            plainBlob[id] = string(clearOrCipherBlob);
        }

        /* Emit event stripped of cleartext for high classifications */
        emit DocumentRegistered(id, classLevel, hp, title, msg.sender);
    }

    /* ---------------- METADATA VIEW ----------------
       Anyone may view harmless metadata (hashPtr + label).
       ------------------------------------------------ */
    function getMeta(uint256 id) external view returns (DocMeta memory) {
        return docs[id];
    }

    /* ---------------- PLAIN CONTENT VIEW ----------------
       * PUBLIC  : anyone with VIEW_ROLE OR owner may read
       * CONF/SEC: nobody – cleartext not on-chain
       --------------------------------------------------- */
    function getPlain(uint256 id)
        external
        view
        returns (string memory)
    {
        DocMeta memory d = docs[id];
        require(d.classLevel == Class.PUBLIC, "Cleartext unavailable");
        require(
            msg.sender == d.owner || hasRole(VIEW_ROLE, msg.sender),
            "No permission"
        );
        return plainBlob[id];
    }

    /* ---------------- INTEGRITY VERIFICATION ----------------
       Any party can prove they possess the original blob without
       revealing it: supply bytes, we hash & compare to stored hashPtr.
       --------------------------------------------------------- */
    function verify(uint256 id, bytes calldata candidate)
        external
        view
        returns (bool)
    {
        return keccak256(candidate) == docs[id].hashPtr;
    }
}

/* ======================================================================
   HOW DLP REQUIREMENTS ARE MET
   ----------------------------------------------------------------------
   • **Data at rest**:  PUBLIC blobs stored, higher classes only a hash.
   • **Data in motion**: Events never broadcast cleartext unless class is
     PUBLIC.  CONFIDENTIAL / SECRET emit only hash pointers.
   • **Data in use**:  RBAC gates both ingestion and retrieval.  Even for
     PUBLIC data, only owner or authorised viewers can fetch the plain text.
   • **Deep-packet‐like inspection**:  `register` computes a content hash and
     enforces policy (e.g., PUBLIC must include cleartext) before acceptance.
   • **Contextual security analysis**:  Each transaction includes attributes
     (originator = `msg.sender`, class label, timestamp) that the centralised
     contract policy evaluates.
   • **Centralised management framework**:  `ADMIN_ROLE` can grant / revoke
     `INGEST_ROLE` and `VIEW_ROLE`, adapting policy across all endpoints.
   • **Prevention, not just detection**:  Attempts to store or retrieve data
     outside policy `revert`, stopping unauthorised use or transmission.
   ====================================================================== */
