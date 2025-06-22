// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SatelliteRelayHub {
    address public operator;
    uint256 public broadcastCount;

    struct RelayMessage {
        bytes32 msgId;
        address origin;
        bytes payload;
        uint256 timestamp;
    }

    mapping(bytes32 => bool) public processed;
    mapping(uint256 => RelayMessage) public broadcasts;

    event MessageBroadcasted(bytes32 indexed msgId, address indexed origin, bytes payload);

    modifier onlyOperator() {
        require(msg.sender == operator, "Not operator");
        _;
    }

    constructor(address _operator) {
        operator = _operator;
    }

    function receiveAndBroadcast(bytes32 msgId, bytes calldata payload) external onlyOperator {
        require(!processed[msgId], "Replay detected");

        processed[msgId] = true;
        broadcasts[broadcastCount++] = RelayMessage(msgId, msg.sender, payload, block.timestamp);

        emit MessageBroadcasted(msgId, msg.sender, payload);
    }

    function getBroadcast(uint256 index) external view returns (
        bytes32 msgId,
        address origin,
        bytes memory payload,
        uint256 timestamp
    ) {
        RelayMessage memory msgData = broadcasts[index];
        return (msgData.msgId, msgData.origin, msgData.payload, msgData.timestamp);
    }
}
