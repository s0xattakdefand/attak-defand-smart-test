// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATA SCIENCE REGISTRY DEMO
   NIST SP 800-218A — “The field that combines domain expertise,
   programming skills, and knowledge of mathematics and statistics to
   extract meaningful insights from data.”
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — UnverifiedDataScienceRegistry
   ⚠️ Anyone can self-declare their skills; no proof of expertise.
----------------------------------------------------------------------------*/
contract UnverifiedDataScienceRegistry {
    mapping(address => string) public profiles;          // free‐form skills description

    event ProfileRegistered(address indexed ds, string skills);

    /// Anyone registers themselves as a “data scientist” with arbitrary text.
    function register(string calldata skills) external {
        profiles[msg.sender] = skills;
        emit ProfileRegistered(msg.sender, skills);
    }

    /// Read a data scientist’s claimed skills.
    function getSkills(address ds) external view returns (string memory) {
        return profiles[ds];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — MiniRoles + ECDSA (helpers for verified registry)
----------------------------------------------------------------------------*/
abstract contract MiniRoles {
    bytes32 public constant ADMIN  = keccak256("ADMIN");
    bytes32 public constant ISSUER = keccak256("ISSUER");  // trusted certifier

    mapping(bytes32 => mapping(address => bool)) internal _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 r) {
        require(_roles[r][msg.sender], "Access denied");
        _;
    }

    constructor() {
        _grant(ADMIN, msg.sender);
    }

    function grantRole(bytes32 r, address a) external onlyRole(ADMIN) {
        _grant(r, a);
    }
    function revokeRole(bytes32 r, address a) external onlyRole(ADMIN) {
        _revoke(r, a);
    }
    function hasRole(bytes32 r, address a) public view returns (bool) {
        return _roles[r][a];
    }

    function _grant(bytes32 r, address a) internal {
        if (!_roles[r][a]) {
            _roles[r][a] = true;
            emit RoleGranted(r, a);
        }
    }
    function _revoke(bytes32 r, address a) internal {
        if (_roles[r][a]) {
            _roles[r][a] = false;
            emit RoleRevoked(r, a);
        }
    }
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — VerifiedDataScienceRegistry
   ✅ Only certificates signed by trusted ISSUERs can register a data scientist’s skills.
----------------------------------------------------------------------------*/
contract VerifiedDataScienceRegistry is MiniRoles {
    using ECDSA for bytes32;

    // Maps practitioner → hash of their skills profile (e.g. IPFS CID, JSON blob)
    mapping(address => bytes32) public skillsHash;

    event Verified(address indexed ds, bytes32 skillsHash, address indexed issuer);

    /**
     * @dev Register a verified data scientist.
     * @param ds            Address of the practitioner.
     * @param skillsHash_   keccak256 hash of their structured skills profile.
     * @param issuerSig     ECDSA signature by a trusted ISSUER over (this contract, ds, skillsHash_).
     */
    function registerVerified(
        address ds,
        bytes32 skillsHash_,
        bytes calldata issuerSig
    ) external {
        // Reconstruct the signed message
        bytes32 msgHash = keccak256(abi.encodePacked(address(this), ds, skillsHash_));
        // Recover signer and verify they hold ISSUER role
        address issuer = msgHash.recover(issuerSig);
        require(hasRole(ISSUER, issuer), "Unknown issuer");

        // Record the verified profile
        skillsHash[ds] = skillsHash_;
        emit Verified(ds, skillsHash_, issuer);
    }

    /** Read the on‐chain hash pointer to a data scientist’s profile. */
    function getVerifiedHash(address ds) external view returns (bytes32) {
        return skillsHash[ds];
    }
}
