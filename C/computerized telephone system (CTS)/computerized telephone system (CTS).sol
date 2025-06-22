// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TeleSignalRouter {
    address public admin;
    mapping(address => bool) public allowedSenders;
    mapping(address => bool) public allowedReceivers;
    mapping(bytes32 => bool) public usedSignals;

    event SignalRouted(address indexed from, address indexed to, bytes4 selector, bytes32 signalHash);
    event SenderAuthorized(address sender);
    event ReceiverAuthorized(address receiver);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function authorizeSender(address sender) external onlyAdmin {
        allowedSenders[sender] = true;
        emit SenderAuthorized(sender);
    }

    function authorizeReceiver(address receiver) external onlyAdmin {
        allowedReceivers[receiver] = true;
        emit ReceiverAuthorized(receiver);
    }

    function routeSignal(address to, bytes calldata payload, uint256 nonce) external {
        require(allowedSenders[msg.sender], "Sender not authorized");
        require(allowedReceivers[to], "Receiver not allowed");

        bytes32 signalHash = keccak256(abi.encodePacked(msg.sender, to, payload, nonce));
        require(!usedSignals[signalHash], "Replay blocked");
        usedSignals[signalHash] = true;

        (bool success, ) = to.call(payload);
        require(success, "Signal failed");

        bytes4 selector = bytes4(payload[:4]);
        emit SignalRouted(msg.sender, to, selector, signalHash);
    }
}
