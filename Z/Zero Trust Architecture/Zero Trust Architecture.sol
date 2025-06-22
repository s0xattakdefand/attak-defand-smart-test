// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title ZeroTrustArchitecture — Modular ZTA with Isolated Roles, Proofs, and Replay Guard
contract ZeroTrustArchitecture is ReentrancyGuard {
    using ECDSA for bytes32;

    address public immutable rootAnchor;
    address public immutable deployer;
    mapping(bytes32 => bool) public usedOps;
    mapping(address => bool) public approvedModules;
    mapping(address => uint256) public accessLevel;

    event ModuleAuthorized(address indexed module);
    event OperationExecuted(bytes32 indexed opHash, address indexed sender);
    event AccessGranted(address indexed to, uint256 level);

    constructor() {
        deployer = msg.sender;
        rootAnchor = keccak256("ZeroTrustArchitecture.Deployed.V1");
        accessLevel[deployer] = 100;
    }

    modifier onlyAdmin() {
        require(accessLevel[msg.sender] >= 100, "Not admin");
        _;
    }

    /// 🔐 Isolated Module Authorization
    function authorizeModule(address module, bytes memory sig) external onlyAdmin {
        bytes32 hash = keccak256(abi.encodePacked("AUTH_MODULE", module)).toEthSignedMessageHash();
        require(hash.recover(sig) == deployer, "Invalid signature");
        approvedModules[module] = true;
        emit ModuleAuthorized(module);
    }

    /// 🔐 Proof-Based Execution w/ Nonce + Expiry
    function secureExecute(bytes calldata data, uint256 expiry, bytes32 nonce, bytes memory sig) external nonReentrant {
        require(block.timestamp <= expiry, "Expired");
        bytes32 opHash = keccak256(abi.encodePacked(msg.sender, data, expiry, nonce)).toEthSignedMessageHash();
        require(!usedOps[opHash], "Replay detected");
        require(opHash.recover(sig) == deployer, "Invalid proof");

        usedOps[opHash] = true;

        (bool ok, ) = address(this).delegatecall(data);
        require(ok, "Execution failed");

        emit OperationExecuted(opHash, msg.sender);
    }

    /// 🔐 Modular-Scoped Role Grant (via internal ZTA logic)
    function grantAccess(address user, uint256 level, bytes memory sig) external {
        bytes32 hash = keccak256(abi.encodePacked("GRANT_ACCESS", user, level)).toEthSignedMessageHash();
        require(hash.recover(sig) == deployer, "Invalid proof");
        accessLevel[user] = level;
        emit AccessGranted(user, level);
    }

    /// Example Secure Operation (Must be internally called by secureExecute)
    function secureAction(uint256 input) external returns (uint256) {
        require(msg.sender == address(this), "ZTA only");
        return input * 3;
    }
}
