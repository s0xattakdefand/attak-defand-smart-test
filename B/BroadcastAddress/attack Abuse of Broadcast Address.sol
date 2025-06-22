contract InsecureBroadcast {
    event UniversalBroadcast(address indexed from, string payload);

    function broadcast(string calldata payload) public {
        emit UniversalBroadcast(msg.sender, payload);
    }
}
