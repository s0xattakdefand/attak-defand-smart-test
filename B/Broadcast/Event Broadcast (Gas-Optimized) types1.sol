contract EventBroadcaster {
    event TopicBroadcast(address indexed user, string topic, string payload);

    function publish(string calldata topic, string calldata payload) external {
        emit TopicBroadcast(msg.sender, topic, payload);
    }
}
