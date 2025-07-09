// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATE OF BIRTH PRIVACY DEMO – FIXED
 * “The date on which a person was born.”
 * Sources: ISO/TS 25237:2008
 *
 * Fixes the bytes memory → bytes calldata error by changing the derive helper
 * to accept bytes memory.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — PublicDOBVault (⚠️ vulnerable; unchanged)
----------------------------------------------------------------------------*/
contract PublicDOBVault {
    mapping(address => uint32) public dateOfBirth; // YYYYMMDD
    event DOBSet(address indexed subject, uint32 dob);

    /// Anyone may set their own (or another’s) DOB.
    function setDOB(address subject, uint32 dob) external {
        dateOfBirth[subject] = dob;
        emit DOBSet(subject, dob);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — MiniPrivacyLib & RolePerUser (helpers)
----------------------------------------------------------------------------*/
library MiniPrivacyLib {
    /// @notice Compute a salted‐hash pointer = keccak256(salt ‖ clearData)
    function derive(bytes32 salt, bytes memory clear) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(salt, clear));
    }
}

abstract contract RolePerUser {
    mapping(address => mapping(address => bool)) internal _viewerAllowed;
    event ViewerGranted(address indexed subject, address indexed viewer);
    event ViewerRevoked(address indexed subject, address indexed viewer);

    modifier onlySubject(address subject) {
        require(msg.sender == subject, "Not data subject");
        _;
    }

    /// Anyone may check if they can view
    function canView(address subject, address viewer) public view returns (bool) {
        return subject == viewer || _viewerAllowed[subject][viewer];
    }

    /// Subject grants a viewer
    function grantViewer(address viewer) external onlySubject(msg.sender) {
        _viewerAllowed[msg.sender][viewer] = true;
        emit ViewerGranted(msg.sender, viewer);
    }

    /// Subject revokes a viewer
    function revokeViewer(address viewer) external onlySubject(msg.sender) {
        _viewerAllowed[msg.sender][viewer] = false;
        emit ViewerRevoked(msg.sender, viewer);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — PrivateDOBRegistry (✅ privacy‐preserving)
----------------------------------------------------------------------------*/
contract PrivateDOBRegistry is RolePerUser {
    using MiniPrivacyLib for bytes32;

    struct Meta {
        bytes32 hashPtr;      // salted‐hash pointer to off‐chain DOB blob
        bytes32 salt;         // per‐subject salt
        uint256 lastUpdated;
    }

    mapping(address => Meta) private _meta;

    event DOBRegistered(address indexed subject, bytes32 hashPtr);
    event SaltRotated(address indexed subject, bytes32 newSalt);
    event DOBDeleted(address indexed subject);

    /// Subject registers their DOB (as uint32) with a chosen salt
    function registerDOB(uint32 dob, bytes32 salt) external {
        bytes memory dobBytes = abi.encodePacked(dob);
        bytes32 ptr = salt.derive(dobBytes);
        _meta[msg.sender] = Meta(ptr, salt, block.timestamp);
        emit DOBRegistered(msg.sender, ptr);
    }

    /// Subject updates DOB (clear or off‐chain) by re‐hashing with the same salt
    function updateDOB(uint32 newDob) external {
        Meta storage m = _meta[msg.sender];
        require(m.salt != bytes32(0), "No DOB registered");
        bytes memory dobBytes = abi.encodePacked(newDob);
        m.hashPtr = m.salt.derive(dobBytes);
        m.lastUpdated = block.timestamp;
        emit DOBRegistered(msg.sender, m.hashPtr);
    }

    /// Subject rotates salt (disassociability), providing current DOB to re‐hash
    function rotateSalt(uint32 dob, bytes32 newSalt) external {
        Meta storage m = _meta[msg.sender];
        require(m.salt != bytes32(0), "No DOB registered");
        bytes memory dobBytes = abi.encodePacked(dob);
        bytes32 newPtr = newSalt.derive(dobBytes);
        m.salt = newSalt;
        m.hashPtr = newPtr;
        m.lastUpdated = block.timestamp;
        emit SaltRotated(msg.sender, newSalt);
        emit DOBRegistered(msg.sender, newPtr);
    }

    /// Subject deletes their DOB record
    function deleteDOB() external {
        delete _meta[msg.sender];
        emit DOBDeleted(msg.sender);
    }

    /// Fetch the pointer metadata; only allowed viewers (or subject) see the salt
    function getMeta(address subject)
        external
        view
        returns (bytes32 hashPtr, uint256 lastUpdated, bool viewerHasSalt, bytes32 salt)
    {
        Meta storage m = _meta[subject];
        hashPtr = m.hashPtr;
        lastUpdated = m.lastUpdated;
        viewerHasSalt = canView(subject, msg.sender);
        salt = viewerHasSalt ? m.salt : bytes32(0);
    }
}
