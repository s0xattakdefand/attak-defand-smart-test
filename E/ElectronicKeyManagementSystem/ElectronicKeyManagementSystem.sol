// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC KEY MANAGEMENT SYSTEM (EKMS)
 *
 *  This single file contains:
 *
 *  1) ElectronicKeyManagementSystemV1  – vulnerable EKMS (no proper access control)
 *  2) EKMSAttacker                     – attacker that hijacks device keys
 *  3) ElectronicKeyManagementSystemV2Defense – secure EKMS with proper roles & rotation rules
 *
 *  Concept:
 *    - "Devices" have electronic keys (e.g., public key hashes) managed on-chain.
 *    - In EKMSv1, anyone can overwrite a device's key (spoofing / hijack).
 *    - EKMSAttacker abuses that to take over a victim device ID.
 *    - EKMSv2Defense fixes this with strict ownership and admin roles.
 */

/* ============================================================= */
/*              1. VULNERABLE ELECTRONIC KEY SYSTEM              */
/* ============================================================= */

contract ElectronicKeyManagementSystemV1 {
    struct KeyRecord {
        bytes32 publicKeyHash; // e.g., hash of the device public key
        bool active;
        uint64 createdAt;
        uint64 updatedAt;
    }

    // deviceId (any address used as device identity) -> key record
    mapping(address => KeyRecord) public keys;

    event KeyRegistered(address indexed deviceId, bytes32 publicKeyHash);
    event KeyRotated(address indexed deviceId, bytes32 oldKeyHash, bytes32 newKeyHash);
    event KeyRevoked(address indexed deviceId, bytes32 oldKeyHash);

    /**
     * @notice Registers or overwrites the key for a device.
     * @dev VULNERABLE:
     *      - No access control: ANYONE can set the key for ANY deviceId.
     *      - This allows a malicious actor to spoof or hijack someone else's device.
     */
    function registerOrOverwriteKey(address deviceId, bytes32 publicKeyHash) external {
        require(deviceId != address(0), "invalid device");
        require(publicKeyHash != bytes32(0), "invalid key");

        KeyRecord storage r = keys[deviceId];

        // If first time, set timestamps
        if (r.createdAt == 0) {
            r.createdAt = uint64(block.timestamp);
        }

        bytes32 old = r.publicKeyHash;
        r.publicKeyHash = publicKeyHash;
        r.active = true;
        r.updatedAt = uint64(block.timestamp);

        if (old == bytes32(0)) {
            emit KeyRegistered(deviceId, publicKeyHash);
        } else {
            emit KeyRotated(deviceId, old, publicKeyHash);
        }
    }

    /**
     * @notice Revokes key for a device.
     * @dev VULNERABLE:
     *      - Again, ANYONE can revoke ANY device's key.
     */
    function revokeKey(address deviceId) external {
        KeyRecord storage r = keys[deviceId];
        require(r.active, "not active");

        bytes32 old = r.publicKeyHash;
        r.active = false;
        r.updatedAt = uint64(block.timestamp);

        emit KeyRevoked(deviceId, old);
    }

    /// @notice Checks whether given keyHash is currently active for deviceId.
    function isKeyActive(address deviceId, bytes32 publicKeyHash) external view returns (bool) {
        KeyRecord storage r = keys[deviceId];
        if (!r.active) return false;
        return r.publicKeyHash == publicKeyHash;
    }
}


/* ============================================================= */
/*                       2. ATTACKER CONTRACT                    */
/* ============================================================= */

contract EKMSAttacker {
    ElectronicKeyManagementSystemV1 public target;
    address public attacker;

    event DeviceHijacked(address indexed targetDevice, bytes32 attackerKeyHash);
    event DeviceKeyRevoked(address indexed targetDevice);

    constructor(address _ekmsV1) {
        target = ElectronicKeyManagementSystemV1(_ekmsV1);
        attacker = msg.sender;
    }

    /**
     * @notice Attacker hijacks a victim device by overwriting its key
     *         with an attacker-controlled key hash.
     *
     * @param victimDevice The deviceId (address) the attacker wants to hijack.
     * @param attackerKeyHash Hash of the attacker's own key (pretending to be device).
     *
     * EFFECT:
     *  - After calling this, any system that trusts EKMSv1 and checks isKeyActive(victimDevice, attackerKeyHash)
     *    will believe the attacker is the legitimate device.
     */
    function hijackDevice(address victimDevice, bytes32 attackerKeyHash) external {
        require(msg.sender == attacker, "not attacker");
        target.registerOrOverwriteKey(victimDevice, attackerKeyHash);
        emit DeviceHijacked(victimDevice, attackerKeyHash);
    }

    /**
     * @notice Attacker can also revoke a legitimate device key to cause denial-of-service.
     */
    function revokeVictimKey(address victimDevice) external {
        require(msg.sender == attacker, "not attacker");
        target.revokeKey(victimDevice);
        emit DeviceKeyRevoked(victimDevice);
    }
}


/* ============================================================= */
/*         3. SECURE ELECTRONIC KEY MANAGEMENT SYSTEM (V2)       */
/* ============================================================= */

contract ElectronicKeyManagementSystemV2Defense {
    struct KeyRecord {
        bytes32 publicKeyHash;
        bool active;
        uint64 createdAt;
        uint64 updatedAt;
        address deviceOwner; // who controls this device's keys
    }

    address public systemAdmin; // global EKMS admin
    mapping(address => KeyRecord) public keys;

    // Optional per-device operator (like an approved manager)
    mapping(address => address) public deviceOperator; // deviceId -> operator

    event DeviceOwnerSet(address indexed deviceId, address indexed owner);
    event DeviceOperatorSet(address indexed deviceId, address indexed operator);
    event KeyRegistered(address indexed deviceId, bytes32 publicKeyHash, address indexed owner);
    event KeyRotated(address indexed deviceId, bytes32 oldKeyHash, bytes32 newKeyHash, address indexed owner);
    event KeyRevoked(address indexed deviceId, bytes32 oldKeyHash, address indexed owner);

    modifier onlySystemAdmin() {
        require(msg.sender == systemAdmin, "not admin");
        _;
    }

    modifier onlyDeviceController(address deviceId) {
        KeyRecord storage r = keys[deviceId];
        // deviceOwner must be set
        require(r.deviceOwner != address(0), "no owner");
        // Either direct device owner or explicit operator
        require(
            msg.sender == r.deviceOwner || msg.sender == deviceOperator[deviceId],
            "not device controller"
        );
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
     * @notice System admin initializes a device and assigns an owner.
     * @dev In a real EKMS, this could represent provisioning a hardware device.
     */
    function setDeviceOwner(address deviceId, address owner) external onlySystemAdmin {
        require(deviceId != address(0), "invalid device");
        require(owner != address(0), "invalid owner");

        KeyRecord storage r = keys[deviceId];

        if (r.createdAt == 0) {
            r.createdAt = uint64(block.timestamp);
        }
        r.deviceOwner = owner;
        r.updatedAt = uint64(block.timestamp);

        emit DeviceOwnerSet(deviceId, owner);
    }

    /**
     * @notice System admin sets an operator for a specific device.
     *         This could be a corporate admin or an automated controller.
     */
    function setDeviceOperator(address deviceId, address operator) external onlySystemAdmin {
        require(deviceId != address(0), "invalid device");
        deviceOperator[deviceId] = operator;
        emit DeviceOperatorSet(deviceId, operator);
    }

    /**
     * @notice Device owner (or operator) registers the first key for the device.
     */
    function registerKey(address deviceId, bytes32 publicKeyHash)
        external
        onlyDeviceController(deviceId)
    {
        require(publicKeyHash != bytes32(0), "invalid key");

        KeyRecord storage r = keys[deviceId];
        require(r.publicKeyHash == bytes32(0), "already has key");

        r.publicKeyHash = publicKeyHash;
        r.active = true;

        if (r.createdAt == 0) {
            r.createdAt = uint64(block.timestamp);
        }
        r.updatedAt = uint64(block.timestamp);

        emit KeyRegistered(deviceId, publicKeyHash, r.deviceOwner);
    }

    /**
     * @notice Device owner (or operator) rotates an existing key to a new one.
     */
    function rotateKey(address deviceId, bytes32 newPublicKeyHash)
        external
        onlyDeviceController(deviceId)
    {
        require(newPublicKeyHash != bytes32(0), "invalid key");

        KeyRecord storage r = keys[deviceId];
        require(r.active, "not active");
        require(r.publicKeyHash != bytes32(0), "no key");

        bytes32 old = r.publicKeyHash;
        r.publicKeyHash = newPublicKeyHash;
        r.updatedAt = uint64(block.timestamp);

        emit KeyRotated(deviceId, old, newPublicKeyHash, r.deviceOwner);
    }

    /**
     * @notice Device owner (or operator) revokes the current key.
     */
    function revokeKey(address deviceId)
        external
        onlyDeviceController(deviceId)
    {
        KeyRecord storage r = keys[deviceId];
        require(r.active, "not active");
        require(r.publicKeyHash != bytes32(0), "no key");

        bytes32 old = r.publicKeyHash;
        r.active = false;
        r.updatedAt = uint64(block.timestamp);

        emit KeyRevoked(deviceId, old, r.deviceOwner);
    }

    /// @notice Returns whether a given key is active for the device.
    function isKeyActive(address deviceId, bytes32 publicKeyHash) external view returns (bool) {
        KeyRecord storage r = keys[deviceId];
        if (!r.active) return false;
        return r.publicKeyHash == publicKeyHash;
    }

    /// @notice Returns the current owner and operator of a device.
    function getDeviceControllers(address deviceId) external view returns (address owner, address operator) {
        owner = keys[deviceId].deviceOwner;
        operator = deviceOperator[deviceId];
    }
}
