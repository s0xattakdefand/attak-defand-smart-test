// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExtensibleAuthenticationProtocolAttackDefense - Attack and Defense Simulation for Extensible Authentication Protocol in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Extensible Authentication (Dynamic accept without validation)
contract InsecureEAP {
    mapping(address => bool) public authenticatedUsers;

    event AuthenticationSuccess(address indexed user, string method);

    function authenticate(string calldata method, bytes calldata data) external {
        // 🔥 Accept any method blindly without real validation
        authenticatedUsers[msg.sender] = true;
        emit AuthenticationSuccess(msg.sender, method);
    }
}

/// @notice Secure Extensible Authentication Protocol (Module Validation, Replay Protection, Immutable Registry)
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureEAP is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant AUTH_MODULE_ROLE = keccak256("AUTH_MODULE_ROLE");

    mapping(bytes32 => bool) public usedAuthAttempts;
    mapping(address => bool) public authenticatedUsers;

    uint256 public constant MAX_AUTH_AGE = 256; // Max block age for session freshness

    event AuthenticationSuccess(address indexed user, string method, bytes32 sessionHash);

    constructor(address[] memory initialAuthModules) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        for (uint256 i = 0; i < initialAuthModules.length; i++) {
            _grantRole(AUTH_MODULE_ROLE, initialAuthModules[i]);
        }
    }

    function authenticate(
        string calldata method,
        bytes32 rawCredential,
        uint256 nonce,
        uint256 providedBlockNumber,
        bytes calldata signature
    ) external {
        require(block.number <= providedBlockNumber + MAX_AUTH_AGE, "Authentication expired");

        bytes32 sessionHash = keccak256(abi.encodePacked(msg.sender, rawCredential, nonce, method, providedBlockNumber, address(this), block.chainid));
        require(!usedAuthAttempts[sessionHash], "Authentication replayed");

        address signer = sessionHash.toEthSignedMessageHash().recover(signature);
        require(hasRole(AUTH_MODULE_ROLE, signer), "Invalid authentication module");

        authenticatedUsers[msg.sender] = true;
        usedAuthAttempts[sessionHash] = true;

        emit AuthenticationSuccess(msg.sender, method, sessionHash);
    }
}

/// @notice Attack contract trying to bypass authentication
contract EAPIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeAuthenticate(string calldata method) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("authenticate(string,bytes)", method, abi.encodePacked("fake"))
        );
    }
}
