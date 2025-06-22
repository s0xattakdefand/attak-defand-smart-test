// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecureCommunicator {
    address public admin;

    mapping(address => bool) public authorizedSenders;
    mapping(bytes32 => bool) public usedMessages; // hash of msg + nonce
    mapping(address => uint256) public nonces;

    event MessageReceived(
        address indexed from,
        address indexed to,
        bytes payload,
        bytes32 indexed msgHash,
        uint256 nonce
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function authorizeSender(address sender) external onlyAdmin {
        authorizedSenders[sender] = true;
    }

    function revokeSender(address sender) external onlyAdmin {
        authorizedSenders[sender] = false;
    }

    function sendMessage(address to, bytes calldata payload) external {
        require(authorizedSenders[msg.sender], "Unauthorized sender");

        uint256 currentNonce = nonces[msg.sender]++;
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, to, payload, currentNonce));
        require(!usedMessages[msgHash], "Replay detected");

        usedMessages[msgHash] = true;

        emit MessageReceived(msg.sender, to, payload, msgHash, currentNonce);
    }

    function verifyMessage(
        address from,
        address to,
        bytes calldata payload,
        uint256 nonce
    ) external view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(from, to, payload, nonce));
        return usedMessages[hash];
    }
}
