// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PassiveSecurityTestingAttackDefense - Attack and Defense Simulation for Passive Security Testing in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract exposing too much metadata
contract InsecurePassiveSecurity {
    address public admin;
    uint256 public privilegedCounter;
    uint256 public gasExposedFlag;

    event PrivilegedAction(address indexed performer, uint256 counter);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    constructor() {
        admin = msg.sender;
    }

    function privilegedAction() external {
        require(msg.sender == admin, "Not admin");
        privilegedCounter += 1;
        gasExposedFlag = privilegedCounter * block.number;
        emit PrivilegedAction(msg.sender, privilegedCounter);
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "Only admin");
        emit AdminChanged(admin, newAdmin);
        admin = newAdmin;
    }
}

/// @notice Secure Contract minimizing metadata and blinding gas profile
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePassiveSecurity is Ownable {
    bytes32 private adminRole;
    mapping(address => bool) private authorized;
    uint256 private counter;
    uint256 private noise; // Gas blinding noise

    event MinimalAction(address indexed performer);

    constructor() {
        adminRole = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        authorized[msg.sender] = true;
    }

    function performAction() external {
        require(authorized[msg.sender], "Not authorized");
        counter += 1;
        noise += uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender, counter))) % 100;
        emit MinimalAction(msg.sender);
    }

    function addAuthorized(address user) external onlyOwner {
        authorized[user] = true;
    }

    function removeAuthorized(address user) external onlyOwner {
        authorized[user] = false;
    }

    function getCounterObfuscated() external view returns (uint256) {
        return counter + noise;
    }
}

/// @notice Passive recon contract simulating metadata and gas profiling
contract PassiveRecon {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function observeAdmin() external view returns (address admin) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("admin()")
        );
        admin = abi.decode(data, (address));
    }

    function observePrivilegedCounter() external view returns (uint256 counter) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("privilegedCounter()")
        );
        counter = abi.decode(data, (uint256));
    }
}
