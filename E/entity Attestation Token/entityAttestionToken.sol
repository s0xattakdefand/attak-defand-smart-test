// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntityAttestationTokenAttackDefense - Attack and Defense Simulation for EATs in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure EAT Verification (No replay protection, no domain binding)
contract InsecureEAT {
    address public trustedAuthority;
    mapping(address => bool) public verifiedEntities;

    event EntityVerified(address indexed entity);

    constructor(address _trustedAuthority) {
        trustedAuthority = _trustedAuthority;
    }

    function verifyEntity(bytes32 messageHash, bytes calldata signature) external {
        address signer = recoverSigner(messageHash, signature);
        require(signer == trustedAuthority, "Invalid authority");

        verifiedEntities[msg.sender] = true;
        emit EntityVerified(msg.sender);
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return hash.toEthSignedMessageHash().recover(signature);
    }
}

/// @notice Secure EAT Verification with Nonce, Expiry, and Domain Binding
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureEAT is Ownable {
    using ECDSA for bytes32;

    address public trustedAuthority;
    mapping(bytes32 => bool) public usedNonces;

    event EntityVerified(address indexed entity, bytes32 nonce);

    constructor(address _trustedAuthority) {
        trustedAuthority = _trustedAuthority;
    }

    struct EAT {
        address entity;
        bytes32 nonce;
        uint256 expiry;
        bytes32 domain;
    }

    bytes32 public immutable DOMAIN_SEPARATOR = keccak256(abi.encodePacked(address(this)));

    function verifyEntity(
        address entity,
        bytes32 nonce,
        uint256 expiry,
        bytes calldata signature
    ) external {
        require(block.timestamp <= expiry, "EAT expired");
        require(!usedNonces[nonce], "EAT already used");

        bytes32 eatHash = keccak256(abi.encodePacked(entity, nonce, expiry, DOMAIN_SEPARATOR));
        address signer = eatHash.toEthSignedMessageHash().recover(signature);

        require(signer == trustedAuthority, "Invalid EAT signer");

        usedNonces[nonce] = true;

        emit EntityVerified(entity, nonce);
    }
}

/// @notice Intruder trying to replay or forge EATs
contract EATIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replayVerify(bytes32 messageHash, bytes calldata signature) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("verifyEntity(bytes32,bytes)", messageHash, signature)
        );
    }
}
