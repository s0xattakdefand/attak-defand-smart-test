// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DecapsulationKeyAttackDefense - Full Attack and Defense Simulation for Decapsulation Key Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Decapsulation System with Key Rotation, Authorization, and Replay Protection
contract SecureDecapsulationKeyManager {
    address public owner;
    uint256 public keyLifetime = 1 days;

    struct DecapsulationKey {
        address keyHolder;
        uint256 expiresAt;
        bool used;
    }

    mapping(bytes32 => DecapsulationKey) public keys;
    mapping(address => bool) public authorizedIssuers;

    event KeyIssued(bytes32 indexed keyId, address indexed keyHolder, uint256 expiresAt);
    event KeyUsed(bytes32 indexed keyId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender], "Not an authorized issuer");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function authorizeIssuer(address issuer) external onlyOwner {
        authorizedIssuers[issuer] = true;
    }

    function revokeIssuer(address issuer) external onlyOwner {
        authorizedIssuers[issuer] = false;
    }

    function issueDecapsulationKey(address keyHolder) external onlyAuthorizedIssuer returns (bytes32 keyId) {
        require(keyHolder != address(0), "Invalid key holder");

        keyId = keccak256(abi.encodePacked(keyHolder, block.timestamp, address(this)));

        keys[keyId] = DecapsulationKey({
            keyHolder: keyHolder,
            expiresAt: block.timestamp + keyLifetime,
            used: false
        });

        emit KeyIssued(keyId, keyHolder, block.timestamp + keyLifetime);
    }

    function decapsulate(bytes32 keyId) external {
        DecapsulationKey storage key = keys[keyId];
        require(key.keyHolder == msg.sender, "Invalid key holder");
        require(!key.used, "Key already used");
        require(block.timestamp <= key.expiresAt, "Key expired");

        key.used = true;

        emit KeyUsed(keyId);

        // Continue decapsulation or decryption logic...
    }

    function isKeyValid(bytes32 keyId) external view returns (bool) {
        DecapsulationKey memory key = keys[keyId];
        return (key.keyHolder != address(0) && !key.used && block.timestamp <= key.expiresAt);
    }
}

/// @notice Attack contract trying to reuse or forge decapsulation keys
contract DecapsulationKeyIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryReuseKey(bytes32 keyId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("decapsulate(bytes32)", keyId)
        );
    }

    function tryForgeKey(bytes32 fakeKeyId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("decapsulate(bytes32)", fakeKeyId)
        );
    }
}
