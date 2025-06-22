// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommsModule {
    address public admin;
    uint32 public domainId;
    mapping(bytes32 => bool) public processed;

    event MessageSent(address indexed from, address indexed to, bytes payload, uint32 toDomain);
    event MessageReceived(bytes32 indexed msgId, address indexed sender, address indexed target);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(uint32 _domainId) {
        admin = msg.sender;
        domainId = _domainId;
    }

    function sendMessage(address to, bytes calldata payload, uint32 toDomain) external {
        emit MessageSent(msg.sender, to, payload, toDomain);
        // Message may be passed to a bridge/relayer system off-chain
    }

    function receiveMessage(
        bytes calldata payload,
        address sender,
        address target,
        uint32 fromDomain,
        bytes32 msgId
    ) external onlyAdmin {
        require(!processed[msgId], "Replay detected");
        require(fromDomain != domainId, "Invalid source domain");

        processed[msgId] = true;

        (bool success, ) = target.call(payload);
        require(success, "Target call failed");

        emit MessageReceived(msgId, sender, target);
    }
}
