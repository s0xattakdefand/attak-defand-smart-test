// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  EXTENDED KEY USAGE (XKU) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ExtendedKeyUsageV1        – vulnerable XKU registry (no ownership / policy)
 *  2) ExtendedKeyUsageAttacker  – attacker that escalates usages for victim
 *  3) ExtendedKeyUsageV2Defense – hardened XKU with owner + allowed mask
 *
 *  Concept:
 *    - Extended Key Usage (XKU) = which purposes a key/cert can be used for:
 *        * digitalSignature
 *        * keyEncipherment
 *        * clientAuth
 *        * serverAuth
 *        * codeSigning
 *        * emailProtection
 *        * timeStamping
 *        * ocspSigning
 *
 *    - V1 BUG: anyone can set/extend usages for any subject (no access control).
 *      → attacker grants themselves powerful usages on a victim subject.
 *    - V2 DEFENSE: subjectOwner + systemAdmin + allowedMask to constrain usages.
 */


/* ============================================================= */
/*             1. VULNERABLE EXTENDED KEY USAGE (V1)             */
/* ============================================================= */

contract ExtendedKeyUsageV1 {
    // We model key usages as bits in a uint256 bitmap.
    // Index mapping (bit positions):
    // 0: digitalSignature
    // 1: keyEncipherment
    // 2: dataEncipherment
    // 3: clientAuth
    // 4: serverAuth
    // 5: codeSigning
    // 6: emailProtection
    // 7: timeStamping
    // 8: ocspSigning

    struct XKURecord {
        uint256 usageBitmap;   // bits for enabled usages
        bool active;
        uint64 createdAt;
        uint64 updatedAt;
    }

    // subject (could be cert hash, device address, etc.) -> XKU
    mapping(address => XKURecord) public xkus;

    event XKUSet(address indexed subject, uint256 bitmap);
    event XKUUsageAdded(address indexed subject, uint8 usageIndex);
    event XKUDeactivated(address indexed subject);

    /**
     * @notice Set usage bitmap for a subject.
     * @dev VULNERABLE:
     *   - No access control: ANY address can call this for ANY subject.
     *   - This means an attacker can silently grant new usages (e.g., codeSigning)
     *     to victims.
     */
    function setUsageBitmap(address subject, uint256 bitmap) external {
        require(subject != address(0), "invalid subject");
        require(bitmap != 0, "empty bitmap");

        XKURecord storage r = xkus[subject];

        if (r.createdAt == 0) {
            r.createdAt = uint64(block.timestamp);
        }

        r.usageBitmap = bitmap;
        r.active = true;
        r.updatedAt = uint64(block.timestamp);

        emit XKUSet(subject, bitmap);
    }

    /**
     * @notice Add a single usage bit for subject (OR operation).
     * @dev VULNERABLE: again, no access control.
     */
    function addUsage(address subject, uint8 usageIndex) external {
        require(subject != address(0), "invalid subject");
        require(usageIndex < 256, "index out of range");

        XKURecord storage r = xkus[subject];

        if (r.createdAt == 0) {
            r.createdAt = uint64(block.timestamp);
        }

        uint256 mask = (uint256(1) << usageIndex);
        r.usageBitmap |= mask;
        r.active = true;
        r.updatedAt = uint64(block.timestamp);

        emit XKUUsageAdded(subject, usageIndex);
    }

    /**
     * @notice Deactivate a subject's XKU.
     * @dev VULNERABLE: anyone can turn off a subject (DoS).
     */
    function deactivate(address subject) external {
        XKURecord storage r = xkus[subject];
        require(r.active, "not active");
        r.active = false;
        r.updatedAt = uint64(block.timestamp);
        emit XKUDeactivated(subject);
    }

    /// @notice Check if subject has a particular usage bit enabled and is active.
    function hasUsage(address subject, uint8 usageIndex) external view returns (bool) {
        require(usageIndex < 256, "index out of range");
        XKURecord storage r = xkus[subject];
        if (!r.active) return false;
        uint256 mask = (uint256(1) << usageIndex);
        return (r.usageBitmap & mask) != 0;
    }

    /// @notice Get raw bitmap for off-chain interpretation.
    function getBitmap(address subject) external view returns (uint256 bitmap, bool active) {
        XKURecord storage r = xkus[subject];
        return (r.usageBitmap, r.active);
    }
}


/* ============================================================= */
/*                      2. ATTACKER CONTRACT                     */
/* ============================================================= */

contract ExtendedKeyUsageAttacker {
    ExtendedKeyUsageV1 public target;
    address public attacker;

    event UsagesEscalated(address indexed victimSubject, uint256 newBitmap);
    event UsageAdded(address indexed victimSubject, uint8 usageIndex);

    constructor(address _v1) {
        target = ExtendedKeyUsageV1(_v1);
        attacker = msg.sender;
    }

    /**
     * @notice Attacker sets an arbitrary bitmap for a victim subject.
     * @dev Example: give victim subject powerful usages like codeSigning (bit 5)
     *               or serverAuth (bit 4), which attacker can then exploit
     *               if external systems rely on XKU alone.
     */
    function escalateAllUsages(address victimSubject, uint256 desiredBitmap) external {
        require(msg.sender == attacker, "not attacker");
        target.setUsageBitmap(victimSubject, desiredBitmap);
        emit UsagesEscalated(victimSubject, desiredBitmap);
    }

    /**
     * @notice Attacker adds a specific usage (e.g., codeSigning) to victim.
     */
    function addUsageToVictim(address victimSubject, uint8 usageIndex) external {
        require(msg.sender == attacker, "not attacker");
        target.addUsage(victimSubject, usageIndex);
        emit UsageAdded(victimSubject, usageIndex);
    }
}


/* ============================================================= */
/*          3. SECURE EXTENDED KEY USAGE (V2 DEFENSE)            */
/* ============================================================= */

contract ExtendedKeyUsageV2Defense {
    struct XKURecord {
        uint256 activeBitmap;   // actual enabled usages
        uint256 allowedBitmap;  // policy: max usages allowed for this subject
        bool active;
        uint64 createdAt;
        uint64 updatedAt;
        address subjectOwner;   // who controls this subject's usages
    }

    address public systemAdmin;
    mapping(address => XKURecord) public xkus;

    event SubjectInitialized(
        address indexed subject,
        address indexed owner,
        uint256 allowedBitmap
    );
    event SubjectOwnerChanged(
        address indexed subject,
        address indexed oldOwner,
        address indexed newOwner
    );
    event UsageBitmapSet(
        address indexed subject,
        uint256 activeBitmap,
        uint256 allowedBitmap
    );
    event UsageAdded(address indexed subject, uint8 usageIndex);
    event XKUDeactivated(address indexed subject);

    modifier onlySystemAdmin() {
        require(msg.sender == systemAdmin, "not admin");
        _;
    }

    modifier onlySubjectOwner(address subject) {
        require(xkus[subject].subjectOwner == msg.sender, "not subject owner");
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
    }

    function transferSystemAdmin(address newAdmin) external onlySystemAdmin {
        require(newAdmin != address(0), "zero");
        systemAdmin = newAdmin;
    }

    /**
     * @notice Admin provisions a subject with an owner and allowed usage mask.
     * @dev allowedBitmap = policy: which bits this subject is ever allowed to have.
     */
    function initializeSubject(
        address subject,
        address owner,
        uint256 allowedBitmap
    ) external onlySystemAdmin {
        require(subject != address(0), "invalid subject");
        require(owner != address(0), "invalid owner");
        require(allowedBitmap != 0, "no allowed usages");

        XKURecord storage r = xkus[subject];

        // Allow re-init only if never used
        require(r.subjectOwner == address(0), "already initialized");

        r.subjectOwner = owner;
        r.allowedBitmap = allowedBitmap;
        r.activeBitmap = 0;
        r.active = false;
        r.createdAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);

        emit SubjectInitialized(subject, owner, allowedBitmap);
    }

    /**
     * @notice Admin can reassign subject owner (e.g., device transfer).
     */
    function changeSubjectOwner(address subject, address newOwner)
        external
        onlySystemAdmin
    {
        require(newOwner != address(0), "invalid owner");
        XKURecord storage r = xkus[subject];
        require(r.subjectOwner != address(0), "not initialized");

        address old = r.subjectOwner;
        r.subjectOwner = newOwner;
        r.updatedAt = uint64(block.timestamp);

        emit SubjectOwnerChanged(subject, old, newOwner);
    }

    /**
     * @notice Subject owner sets an active bitmap, constrained by allowedBitmap.
     */
    function setActiveBitmap(address subject, uint256 newBitmap)
        external
        onlySubjectOwner(subject)
    {
        XKURecord storage r = xkus[subject];
        require(r.allowedBitmap != 0, "subject policy missing");

        // Enforce policy: cannot enable bits outside allowedBitmap
        require((newBitmap & ~r.allowedBitmap) == 0, "exceeds allowed usages");

        r.activeBitmap = newBitmap;
        r.active = newBitmap != 0;
        r.updatedAt = uint64(block.timestamp);

        emit UsageBitmapSet(subject, newBitmap, r.allowedBitmap);
    }

    /**
     * @notice Subject owner adds a single usage bit, must be within allowedBitmap.
     */
    function addUsage(address subject, uint8 usageIndex)
        external
        onlySubjectOwner(subject)
    {
        require(usageIndex < 256, "index out of range");
        XKURecord storage r = xkus[subject];
        require(r.allowedBitmap != 0, "subject policy missing");

        uint256 mask = (uint256(1) << usageIndex);
        require((mask & r.allowedBitmap) != 0, "usage not allowed by policy");

        r.activeBitmap |= mask;
        r.active = true;
        r.updatedAt = uint64(block.timestamp);

        emit UsageAdded(subject, usageIndex);
    }

    /**
     * @notice Subject owner can fully deactivate XKU (no usages active).
     */
    function deactivate(address subject)
        external
        onlySubjectOwner(subject)
    {
        XKURecord storage r = xkus[subject];
        require(r.active, "already inactive");

        r.activeBitmap = 0;
        r.active = false;
        r.updatedAt = uint64(block.timestamp);

        emit XKUDeactivated(subject);
    }

    /// @notice Check if subject has a particular active usage.
    function hasUsage(address subject, uint8 usageIndex) external view returns (bool) {
        require(usageIndex < 256, "index out of range");
        XKURecord storage r = xkus[subject];
        if (!r.active) return false;
        uint256 mask = (uint256(1) << usageIndex);
        return (r.activeBitmap & mask) != 0;
    }

    /// @notice Get both active and allowed bitmaps for auditing.
    function getBitmaps(address subject)
        external
        view
        returns (uint256 activeBitmap, uint256 allowedBitmap, bool active)
    {
        XKURecord storage r = xkus[subject];
        return (r.activeBitmap, r.allowedBitmap, r.active);
    }

    /// @notice Get subject owner and timestamps for auditing.
    function getSubjectMeta(address subject)
        external
        view
        returns (
            address subjectOwner,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        XKURecord storage r = xkus[subject];
        return (r.subjectOwner, r.createdAt, r.updatedAt);
    }
}
