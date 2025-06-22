// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SignatureValidationAuthorizationAttackDefense - Attack and Defense Simulation for Signature Validation and Authorization Checks in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure contract enforcing strict signature validation and role authorization
contract SecureSignatureAuthorization {
    address public owner;
    mapping(address => bool) public authorizedSigners;
    mapping(address => uint256) public nonces;

    event ActionExecuted(address indexed signer, uint256 indexed nonce, string action);

    constructor() {
        owner = msg.sender;
        authorizedSigners[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function addAuthorizedSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
    }

    function removeAuthorizedSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = false;
    }

    function executeAction(
        uint256 userNonce,
        string calldata action,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(
            abi.encodePacked(msg.sender, userNonce, action, address(this))
        );

        bytes32 ethSignedDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        address recoveredSigner = ecrecover(ethSignedDigest, v, r, s);
        require(recoveredSigner == msg.sender, "Invalid signer");
        require(authorizedSigners[recoveredSigner], "Signer not authorized");
        require(userNonce == nonces[msg.sender], "Invalid nonce");

        nonces[msg.sender] += 1;

        emit ActionExecuted(recoveredSigner, userNonce, action);
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}

/// @notice Attack contract trying to replay or forge signatures without authorization
contract SignatureIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try to re-use an old signature without incrementing nonce
    function tryReplayAttack(
        uint256 oldNonce,
        string calldata oldAction,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature(
                "executeAction(uint256,string,uint8,bytes32,bytes32)",
                oldNonce,
                oldAction,
                v,
                r,
                s
            )
        );
    }
}
