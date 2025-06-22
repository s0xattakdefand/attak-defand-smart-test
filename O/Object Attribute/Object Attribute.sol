// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectAttributeAttackDefense - Full Attack and Defense Simulation for Object Attribute Misuse in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Object Attribute Handling (No Access Control, Mutable Critical Fields)
contract InsecureObjectAttribute {
    struct User {
        address owner;
        uint256 balance;
        bool isWhitelisted;
    }

    mapping(address => User) public users;

    event UserCreated(address indexed user, uint256 balance);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event WhitelistStatusChanged(address indexed user, bool status);

    function createUser(uint256 initialBalance) external {
        users[msg.sender] = User(msg.sender, initialBalance, false);
        emit UserCreated(msg.sender, initialBalance);
    }

    function changeOwner(address user, address newOwner) external {
        // 🔥 Anyone can change any user's owner attribute!
        users[user].owner = newOwner;
        emit OwnerChanged(user, newOwner);
    }

    function whitelist(address user, bool status) external {
        // 🔥 No restrictions!
        users[user].isWhitelisted = status;
        emit WhitelistStatusChanged(user, status);
    }
}

/// @notice Secure Object Attribute Handling (Access Controlled, Immutable Critical Fields)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectAttribute is Ownable {
    struct User {
        address owner;
        uint256 balance;
        bool isWhitelisted;
    }

    mapping(address => User) private users;

    event UserCreated(address indexed user, uint256 balance);
    event WhitelistStatusChanged(address indexed user, bool status);

    function createUser(uint256 initialBalance) external {
        require(users[msg.sender].owner == address(0), "Already created");
        users[msg.sender] = User(msg.sender, initialBalance, false);
        emit UserCreated(msg.sender, initialBalance);
    }

    function whitelist(address user, bool status) external onlyOwner {
        require(users[user].owner != address(0), "User not registered");
        users[user].isWhitelisted = status;
        emit WhitelistStatusChanged(user, status);
    }

    function getUser(address user) external view returns (address owner_, uint256 balance_, bool whitelisted_) {
        User memory u = users[user];
        return (u.owner, u.balance, u.isWhitelisted);
    }
}

/// @notice Attack contract simulating attribute hijack
contract AttributeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackOwnership(address victim, address newFakeOwner) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("changeOwner(address,address)", victim, newFakeOwner)
        );
    }

    function fakeWhitelist(address victim) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("whitelist(address,bool)", victim, true)
        );
    }
}
