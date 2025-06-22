// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GaloisMACAttackDefense - Full Attack and Defense Simulation for Galois Message Authentication Code in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure GMAC Simulation (No Nonce Control, No Source Binding)
contract InsecureGaloisMAC {
    mapping(bytes32 => bool) public usedMACs;

    event MessageAuthenticated(address indexed user, string message, bytes32 mac);

    function submitMessage(string memory message, bytes32 mac) external {
        require(!usedMACs[mac], "MAC already used"); // basic replay check

        // BAD: No binding to sender, nonce, or timestamp
        usedMACs[mac] = true;
        emit MessageAuthenticated(msg.sender, message, mac);
    }
}

/// @notice Secure GMAC Simulation (Nonce, Sender, Context Bound)
contract SecureGaloisMAC {
    address public immutable admin;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedMACs;

    event MessageAuthenticatedSecurely(address indexed user, string message, bytes32 mac, uint256 nonce);

    constructor() {
        admin = msg.sender;
    }

    function submitMessage(string memory message, bytes32 mac, uint256 nonce) external {
        require(nonce == nonces[msg.sender], "Invalid or reused nonce");

        bytes32 expectedMAC = keccak256(abi.encodePacked(msg.sender, message, nonce, address(this)));

        require(expectedMAC == mac, "Invalid MAC");
        require(!usedMACs[mac], "MAC already used");

        usedMACs[mac] = true;
        nonces[msg.sender] += 1;

        emit MessageAuthenticatedSecurely(msg.sender, message, mac, nonce);
    }
}

/// @notice Attack contract simulating GMAC replay/fake submission
contract GaloisMACIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeMAC(string memory fakeMessage, bytes32 fakeMac) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitMessage(string,bytes32)", fakeMessage, fakeMac)
        );
    }
}
