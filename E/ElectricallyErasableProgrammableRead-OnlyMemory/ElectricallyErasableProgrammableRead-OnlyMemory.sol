// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *   "Electrically Erasable Programmable Read-Only Memory (EEPROM)"
 *
 * EEPROM model:
 *   - Slots store 32-byte data.
 *   - Erasing sets slot to 0x00..00.
 *   - Programming writes new value.
 *
 * INSECURE VERSION:
 *   - Anyone can write to any slot.
 *   - Anyone can erase any slot.
 *   - Anyone can "lock/unlock" memory.
 *   - No integrity or role enforcement.
 *
 * SECURE VERSION:
 *   - Only firmware owner can modify EEPROM.
 *   - Integrity: hash of entire EEPROM tracked.
 *   - Optional write-once (OTP) lock.
 *   - Authorized technicians can unlock temporarily.
 */

/*//////////////////////////////////////////////////////////////
//                     INSECURE EEPROM MODULE
//////////////////////////////////////////////////////////////*/

contract EEPROMInsecure {
    mapping(uint256 => bytes32) public memorySlot;
    mapping(uint256 => bool) public slotLocked;

    event SlotWritten(uint256 slot, bytes32 value);
    event SlotErased(uint256 slot);
    event SlotLocked(uint256 slot, bool locked);

    /**
     * ⚠ Anyone can write to any memory slot.
     */
    function writeSlot(uint256 slot, bytes32 value) external {
        require(!slotLocked[slot], "LOCKED");
        memorySlot[slot] = value;
        emit SlotWritten(slot, value);
    }

    /**
     * ⚠ Anyone can erase any memory slot.
     */
    function eraseSlot(uint256 slot) external {
        require(!slotLocked[slot], "LOCKED");
        memorySlot[slot] = bytes32(0);
        emit SlotErased(slot);
    }

    /**
     * ⚠ Anyone can lock/unlock any slot.
     */
    function setLock(uint256 slot, bool locked) external {
        slotLocked[slot] = locked;
        emit SlotLocked(slot, locked);
    }

    /**
     * Primitive integrity check (always attacker-controllable).
     */
    function readSlot(uint256 slot) external view returns (bytes32) {
        return memorySlot[slot];
    }
}

/*//////////////////////////////////////////////////////////////
//                            OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                   SECURE EEPROM MODULE (DEFENDED)
//////////////////////////////////////////////////////////////*/

contract EEPROMSecure is Ownable {
    mapping(uint256 => bytes32) private memorySlot;
    mapping(uint256 => bool) public slotLocked;        // one-time programmable lock
    mapping(address => bool) public isTechnician;      // can temporarily unlock

    bool public globalLock;  // final firmware freeze

    event SlotWritten(uint256 slot, bytes32 value);
    event SlotErased(uint256 slot);
    event SlotLocked(uint256 slot);
    event TechnicianSet(address who, bool allowed);
    event GlobalLockActivated();

    modifier onlyTechOrOwner() {
        require(msg.sender == owner || isTechnician[msg.sender], "NOT_AUTH");
        _;
    }

    modifier notGloballyLocked() {
        require(!globalLock, "FIRMWARE_FROZEN");
        _;
    }

    /**
     * Owner assigns trusted technicians.
     */
    function setTechnician(address who, bool allowed) external onlyOwner {
        require(who != address(0), "ZERO");
        isTechnician[who] = allowed;
        emit TechnicianSet(who, allowed);
    }

    /**
     * Owner can permanently freeze EEPROM (no further writes).
     */
    function activateGlobalLock() external onlyOwner {
        globalLock = true;
        emit GlobalLockActivated();
    }

    /**
     * Write into EEPROM:
     *   - slot must not be permanently locked
     *   - global firmware lock must be off
     */
    function writeSlot(uint256 slot, bytes32 value)
        external
        onlyTechOrOwner
        notGloballyLocked
    {
        require(!slotLocked[slot], "SLOT_LOCKED");
        memorySlot[slot] = value;
        emit SlotWritten(slot, value);
    }

    /**
     * Erase EEPROM slot (sets to zero).
     */
    function eraseSlot(uint256 slot)
        external
        onlyTechOrOwner
        notGloballyLocked
    {
        require(!slotLocked[slot], "SLOT_LOCKED");
        memorySlot[slot] = bytes32(0);
        emit SlotErased(slot);
    }

    /**
     * One-Time-Programmable (OTP) lock:
     * Once locked, it cannot be unlocked.
     */
    function lockSlot(uint256 slot) external onlyOwner notGloballyLocked {
        slotLocked[slot] = true;
        emit SlotLocked(slot);
    }

    /**
     * Read memory content (viewable by all).
     */
    function readSlot(uint256 slot) external view returns (bytes32) {
        return memorySlot[slot];
    }

    /**
     * Hash of entire EEPROM region for integrity checks.
     * Example: compute hash of first 1024 slots.
     */
    function computeRegionHash(uint256 slots)
        external
        view
        returns (bytes32 h)
    {
        bytes memory buf = new bytes(slots * 32);

        for (uint256 i; i < slots; i++) {
            bytes32 val = memorySlot[i];
            assembly {
                mstore(add(buf, add(32, mul(i, 32))), val)
            }
        }

        return keccak256(buf);
    }
}

/*//////////////////////////////////////////////////////////////
//                        ATTACKER CONTRACT
//////////////////////////////////////////////////////////////*/

contract EEPROMAttacker {
    EEPROMInsecure public target;

    constructor(address _target) {
        target = EEPROMInsecure(_target);
    }

    /**
     * Step 1 — freely write malicious data.
     */
    function poisonSlot(uint256 slot, bytes32 payload) public {
        target.writeSlot(slot, payload);
    }

    /**
     * Step 2 — erase legitimate firmware data.
     */
    function eraseLegit(uint256 slot) public {
        target.eraseSlot(slot);
    }

    /**
     * Step 3 — override slot lock to prevent correction.
     */
    function lockDamage(uint256 slot) public {
        target.setLock(slot, true);
    }

    /**
     * Full exploit: override firmware, erase originals, lock firmware.
     */
    function fullAttack(uint256 slot, bytes32 payload) external {
        poisonSlot(slot, payload);
        eraseLegit(slot + 1);
        lockDamage(slot);
    }
}
