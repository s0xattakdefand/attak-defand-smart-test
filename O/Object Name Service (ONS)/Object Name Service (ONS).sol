// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectNameServiceAttackDefense - Full Attack and Defense Simulation for Object Name Services in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Object Name Service (Anyone Can Steal or Modify Names)
contract InsecureObjectNameService {
    mapping(string => address) public nameToAddress;

    event NameRegistered(string indexed name, address indexed owner);
    event NameUpdated(string indexed name, address indexed newOwner);

    function registerName(string calldata name) external {
        nameToAddress[name] = msg.sender;
        emit NameRegistered(name, msg.sender);
    }

    function updateName(string calldata name, address newOwner) external {
        // 🔥 No ownership verification!
        nameToAddress[name] = newOwner;
        emit NameUpdated(name, newOwner);
    }

    function resolveName(string calldata name) external view returns (address) {
        return nameToAddress[name];
    }
}

/// @notice Secure Object Name Service (Strict Ownership, Commit-Reveal Optional Layer)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectNameService is Ownable {
    struct NameRecord {
        address owner;
        uint256 registeredAt;
    }

    mapping(string => NameRecord) private records;

    event NameRegistered(string indexed name, address indexed owner);
    event NameTransferred(string indexed name, address indexed oldOwner, address indexed newOwner);

    modifier onlyNameOwner(string memory name) {
        require(records[name].owner == msg.sender, "Not the owner");
        _;
    }

    function registerName(string calldata name) external {
        require(records[name].owner == address(0), "Name already registered");
        records[name] = NameRecord(msg.sender, block.timestamp);
        emit NameRegistered(name, msg.sender);
    }

    function transferName(string calldata name, address newOwner) external onlyNameOwner(name) {
        require(newOwner != address(0), "Invalid new owner");
        address oldOwner = records[name].owner;
        records[name].owner = newOwner;
        emit NameTransferred(name, oldOwner, newOwner);
    }

    function resolveName(string calldata name) external view returns (address owner, uint256 registeredAt) {
        NameRecord memory record = records[name];
        return (record.owner, record.registeredAt);
    }
}

/// @notice Attack contract simulating name hijacking
contract NameServiceIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackName(string calldata name, address fakeOwner) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateName(string,address)", name, fakeOwner)
        );
    }
}
