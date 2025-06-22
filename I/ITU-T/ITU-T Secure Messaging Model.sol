pragma solidity ^0.8.21;

contract SecureMessagingITU {
    event MessageSent(address indexed from, address indexed to, string topic, string payload, uint256 timestamp);

    function sendMessage(address to, string memory topic, string memory payload) external {
        require(bytes(payload).length <= 1024, "Payload too large");
        emit MessageSent(msg.sender, to, topic, payload, block.timestamp);
    }
}
