// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IdentificationAttackDefense - Full Attack and Defense Simulation for Identity in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Identification Contract (Weak or No Identity Validation)
contract InsecureIdentification {
    mapping(address => bool) public registered;

    event UserRegistered(address indexed user);

    function register() external {
        registered[msg.sender] = true;
        emit UserRegistered(msg.sender);
    }

    function isRegistered(address user) external view returns (bool) {
        return registered[user];
    }
}

/// @notice Secure Identification Contract (Signature Proof Binding)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureIdentification {
    using ECDSA for bytes32;

    address public owner;
    mapping(address => bool) public registered;
    mapping(address => uint256) public nonces;

    bytes32 public constant DOMAIN_SEPARATOR = keccak256("SecureIdentification_v1");

    event UserRegistered(address indexed user, uint256 nonce);

    constructor() {
        owner = msg.sender;
    }

    function register(address user, uint256 nonce, bytes memory signature) external {
        require(!registered[user], "Already registered");
        require(nonce == nonces[user], "Invalid nonce");

        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, user, nonce));
        address recovered = hash.toEthSignedMessageHash().recover(signature);

        require(recovered == user, "Signature mismatch");

        registered[user] = true;
        nonces[user]++;
        emit UserRegistered(user, nonce);
    }

    function isRegistered(address user) external view returns (bool) {
        return registered[user];
    }
}

/// @notice Attack contract simulating identity hijack or signature replay
contract IdentificationIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeRegister() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("register()")
        );
    }
}
