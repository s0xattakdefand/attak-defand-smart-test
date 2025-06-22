contract InsecureBroadcaster {
    event Broadcast(address indexed sender, string message);

    function broadcast(string calldata message) public {
        emit Broadcast(msg.sender, message);
    }
}
