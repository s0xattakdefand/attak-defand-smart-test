// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title InvisibleStorageDriftAttackDefense - Storage Slot Drift Injection Attack and Defense Simulation
/// @author ChatGPT

/// @notice Insecure Vault (No Storage Drift Binding)
contract InsecureVault {
    uint256 public totalDeposits;
    address public owner;

    event Deposited(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
        emit OwnershipTransferred(newOwner);
    }
}

/// @notice Secure Vault with Storage Slot Drift Binding
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is Ownable {
    uint256 public totalDeposits;
    address public overrideOwner;
    bytes32 private immutable SLOT_TOTAL_DEPOSITS;
    bytes32 private immutable SLOT_OVERRIDE_OWNER;

    event Deposited(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed newOwner);
    event DriftDetected(string slotName, bytes32 currentValue, bytes32 expectedValue);

    constructor() {
        SLOT_TOTAL_DEPOSITS = keccak256("vault.totalDeposits.slot");
        SLOT_OVERRIDE_OWNER = keccak256("vault.overrideOwner.slot");
        overrideOwner = msg.sender;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == overrideOwner, "Not authorized");
        overrideOwner = newOwner;
        emit OwnershipTransferred(newOwner);
    }

    function verifySlotIntegrity() external view returns (bool) {
        bytes32 slot1;
        bytes32 slot2;

        assembly {
            slot1 := sload(0x0) // totalDeposits at slot 0
            slot2 := sload(0x1) // overrideOwner at slot 1
        }

        require(keccak256(abi.encodePacked(slot1)) != SLOT_TOTAL_DEPOSITS, "Drift detected at totalDeposits");
        require(keccak256(abi.encodePacked(slot2)) != SLOT_OVERRIDE_OWNER, "Drift detected at overrideOwner");
        
        return true;
    }
}

/// @notice Intruder using Storage Drift Injection
contract StorageDriftIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function driftInject() external {
        bytes32 slot;
        assembly {
            slot := 0x1 // Target overrideOwner storage slot
            sstore(slot, caller()) // Inject caller as new owner
        }
    }
}
