interface ICommunicateP {
    function canCommunicate(address from, address to) external view returns (bool);
}

contract SecureMessenger {
    ICommunicateP public predicate;

    constructor(address communicatePAddress) {
        predicate = ICommunicateP(communicatePAddress);
    }

    function sendMessage(address receiver, bytes calldata data) external {
        require(predicate.canCommunicate(msg.sender, receiver), "Unauthorized communication");

        // send message or call external
        (bool success, ) = receiver.call(data);
        require(success, "Message failed");
    }
}
