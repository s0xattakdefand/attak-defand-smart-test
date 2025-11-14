// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Encrypting File System"
 *
 * Model:
 *  - We manage ENCRYPTION POLICY for storage volumes:
 *      * volumeId               (bytes32)
 *      * owner                  (who owns that volume/policy)
 *      * encryptionEnabled      (on/off)
 *      * key / keyId            (insecure vs secure)
 *      * lastRotationTimestamp  (key rotation time)
 *      * compliant              (meets policy)
 *
 * Insecure version mistakes:
 *  - Raw key stored on-chain.
 *  - Anyone can change encryption policy for any volume.
 *  - Anyone can mark volume as "compliant".
 *  - No rotation rules or enforcement.
 *
 * Secure version:
 *  - Uses keyId instead of raw key.
 *  - Admin-only policy configuration.
 *  - Owner + admin control updates.
 *  - Enforces minimal rotation interval.
 */

/*//////////////////////////////////////////////////////////////
//                  INSECURE ENCRYPTING FS
//////////////////////////////////////////////////////////////*/

contract EncryptingFSInsecure {
    struct Volume {
        address owner;             // who "owns" this volume policy
        bool encryptionEnabled;    // encryption flag
        bytes32 rawKey;            // ⚠️ raw key stored on-chain (bad)
        uint256 lastRotation;      // last key rotation timestamp
        bool compliant;            // "meets policy"
    }

    // volumeId => Volume
    mapping(bytes32 => Volume) public volumes;

    event VolumeRegistered(bytes32 indexed volumeId, address indexed owner);
    event VolumePolicyUpdated(bytes32 indexed volumeId, bool encryptionEnabled, bytes32 rawKey);
    event VolumeComplianceSet(bytes32 indexed volumeId, bool compliant);
    event VolumeKeyRotated(bytes32 indexed volumeId, bytes32 newKey, uint256 timestamp);

    /**
     * ⚠️ VULN #1:
     * Anyone can register or overwrite any volumeId and become owner.
     */
    function registerVolume(bytes32 volumeId) external {
        volumes[volumeId].owner = msg.sender;
        // Initialize with some defaults
        volumes[volumeId].encryptionEnabled = false;
        volumes[volumeId].rawKey = bytes32(0);
        volumes[volumeId].lastRotation = block.timestamp;
        volumes[volumeId].compliant = false;

        emit VolumeRegistered(volumeId, msg.sender);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can change encryption policy and raw key for any volume.
     */
    function setPolicy(
        bytes32 volumeId,
        bool encryptionEnabled,
        bytes32 rawKey
    ) external {
        Volume storage v = volumes[volumeId];
        v.owner = msg.sender; // attacker becomes owner
        v.encryptionEnabled = encryptionEnabled;
        v.rawKey = rawKey;

        emit VolumePolicyUpdated(volumeId, encryptionEnabled, rawKey);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can mark any volume as compliant.
     */
    function setCompliance(bytes32 volumeId, bool compliant) external {
        volumes[volumeId].compliant = compliant;
        emit VolumeComplianceSet(volumeId, compliant);
    }

    /**
     * ⚠️ VULN #4:
     * Anyone can rotate key at any time with any key.
     */
    function rotateKey(bytes32 volumeId, bytes32 newKey) external {
        Volume storage v = volumes[volumeId];
        v.rawKey = newKey;
        v.lastRotation = block.timestamp;

        emit VolumeKeyRotated(volumeId, newKey, block.timestamp);
    }

    /**
     * ⚠️ VULN #5:
     * Raw key is fully readable on-chain.
     */
    function getRawKey(bytes32 volumeId) external view returns (bytes32) {
        return volumes[volumeId].rawKey;
    }

    /**
     * "Secure" check that is fully attacker-controlled.
     */
    function isSecure(bytes32 volumeId) external view returns (bool) {
        Volume memory v = volumes[volumeId];
        // naive: must be encrypted, compliant, and key != zero
        return v.encryptionEnabled && v.compliant && v.rawKey != bytes32(0);
    }
}

/*//////////////////////////////////////////////////////////////
//                           OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                  SECURE ENCRYPTING FS VERSION
//////////////////////////////////////////////////////////////*/

contract EncryptingFSSecure is Ownable {
    struct Volume {
        address volumeOwner;       // logical owner (customer, tenant, device owner)
        bool encryptionEnabled;
        bytes32 keyId;             // ID in external KMS/HSM, NOT raw key
        uint256 lastRotation;
        bool compliant;
        bool exists;
    }

    // volumeId => Volume
    mapping(bytes32 => Volume) public volumes;

    // minimal rotation interval (e.g. 30 days)
    uint256 public minRotationInterval = 30 days;

    // optional: who can act as backend/service to update policies
    mapping(address => bool) public isPolicyAgent;

    event PolicyAgentSet(address indexed agent, bool allowed);
    event VolumeRegistered(bytes32 indexed volumeId, address indexed volumeOwner);
    event VolumePolicyUpdated(bytes32 indexed volumeId, bool encryptionEnabled, bytes32 keyId);
    event VolumeComplianceSet(bytes32 indexed volumeId, bool compliant);
    event VolumeKeyRotated(bytes32 indexed volumeId, bytes32 keyId, uint256 timestamp);
    event MinRotationIntervalUpdated(uint256 oldInterval, uint256 newInterval);

    modifier onlyAgentOrOwner(bytes32 volumeId) {
        Volume storage v = volumes[volumeId];
        require(v.exists, "VOLUME_NOT_EXIST");
        require(
            msg.sender == v.volumeOwner || isPolicyAgent[msg.sender] || msg.sender == owner,
            "NO_PERMISSION"
        );
        _;
    }

    /**
     * Admin configures policy agents (backend services).
     */
    function setPolicyAgent(address agent, bool allowed) external onlyOwner {
        require(agent != address(0), "ZERO_ADDRESS");
        isPolicyAgent[agent] = allowed;
        emit PolicyAgentSet(agent, allowed);
    }

    /**
     * Admin registers a volume and sets its logical owner.
     */
    function registerVolume(bytes32 volumeId, address volumeOwner) external onlyOwner {
        require(volumeOwner != address(0), "BAD_OWNER");
        Volume storage v = volumes[volumeId];
        require(!v.exists, "VOLUME_EXISTS");

        v.volumeOwner = volumeOwner;
        v.encryptionEnabled = false;
        v.keyId = bytes32(0);
        v.lastRotation = 0;
        v.compliant = false;
        v.exists = true;

        emit VolumeRegistered(volumeId, volumeOwner);
    }

    /**
     * Admin or policy agent or volumeOwner can set encryptionEnabled and keyId.
     * No raw key is stored; keyId is just a reference to external KMS/HSM.
     */
    function setPolicy(
        bytes32 volumeId,
        bool encryptionEnabled,
        bytes32 keyId
    ) external onlyAgentOrOwner(volumeId) {
        Volume storage v = volumes[volumeId];
        require(keyId != bytes32(0), "EMPTY_KEY_ID");
        v.encryptionEnabled = encryptionEnabled;
        v.keyId = keyId;

        emit VolumePolicyUpdated(volumeId, encryptionEnabled, keyId);
    }

    /**
     * Rotate keyId with minimal interval between rotations.
     */
    function rotateKey(bytes32 volumeId, bytes32 newKeyId)
        external
        onlyAgentOrOwner(volumeId)
    {
        Volume storage v = volumes[volumeId];
        require(newKeyId != bytes32(0), "EMPTY_KEY_ID");

        // enforce minimal rotation interval if previous rotation exists
        if (v.lastRotation != 0) {
            require(
                block.timestamp >= v.lastRotation + minRotationInterval,
                "ROTATION_TOO_SOON"
            );
        }

        v.keyId = newKeyId;
        v.lastRotation = block.timestamp;

        emit VolumeKeyRotated(volumeId, newKeyId, block.timestamp);
    }

    /**
     * Admin sets compliance status after external checks.
     */
    function setCompliance(bytes32 volumeId, bool compliant) external onlyOwner {
        Volume storage v = volumes[volumeId];
        require(v.exists, "VOLUME_NOT_EXIST");

        v.compliant = compliant;
        emit VolumeComplianceSet(volumeId, compliant);
    }

    /**
     * Admin can tune rotation interval.
     */
    function setMinRotationInterval(uint256 newInterval) external onlyOwner {
        require(newInterval > 0, "BAD_INTERVAL");
        uint256 old = minRotationInterval;
        minRotationInterval = newInterval;
        emit MinRotationIntervalUpdated(old, newInterval);
    }

    /**
     * Secure "is volume policy OK?" check:
     *  - volume exists
     *  - encryption enabled
     *  - keyId present
     *  - compliant flag set
     *  - lastRotation not too old (example: must have rotated at least once)
     */
    function isSecure(bytes32 volumeId) external view returns (bool) {
        Volume memory v = volumes[volumeId];
        if (!v.exists) return false;
        if (!v.encryptionEnabled) return false;
        if (v.keyId == bytes32(0)) return false;
        if (!v.compliant) return false;

        // example: require at least one rotation in history
        if (v.lastRotation == 0) return false;

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EncryptingFSAttacker {
    EncryptingFSInsecure public target;

    constructor(address _target) {
        target = EncryptingFSInsecure(_target);
    }

    /**
     * Attack #1:
     * Register a volumeId and take ownership (or overwrite existing owner).
     */
    function hijackVolume(bytes32 volumeId) public {
        target.registerVolume(volumeId);
    }

    /**
     * Attack #2:
     * Set encryption policy with attacker-controlled raw key & mark as compliant.
     */
    function setFakeSecurePolicy(bytes32 volumeId) public {
        // set encryption on with some "key"
        target.setPolicy(volumeId, true, keccak256(abi.encodePacked("attacker-key")));
        // mark compliant
        target.setCompliance(volumeId, true);
    }

    /**
     * Attack #3:
     * Rotate key arbitrarily (no interval enforcement).
     */
    function spamRotateKey(bytes32 volumeId) public {
        bytes32 newKey = keccak256(abi.encodePacked("rotated-", block.timestamp, msg.sender));
        target.rotateKey(volumeId, newKey);
    }

    /**
     * Attack #4:
     * Read victim's raw key directly.
     */
    function stealRawKey(bytes32 volumeId) public view returns (bytes32) {
        return target.getRawKey(volumeId);
    }

    /**
     * Full exploit flow:
     *   1) hijack volume or register new
     *   2) set fake secure policy
     *   3) optionally rotate key
     *
     * After this, target.isSecure(volumeId) will likely be true.
     */
    function fullAttack(bytes32 volumeId) external {
        hijackVolume(volumeId);
        setFakeSecurePolicy(volumeId);
        spamRotateKey(volumeId);
    }
}
