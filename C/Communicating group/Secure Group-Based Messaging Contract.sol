interface IGroupRegistry {
    function isGroupMember(bytes32 groupId, address member) external view returns (bool);
}

contract SecureMessenger {
    bytes32 public groupId;
    IGroupRegistry public group;

    constructor(bytes32 _groupId, address groupRegistry) {
        groupId = _groupId;
        group = IGroupRegistry(groupRegistry);
    }

    modifier onlyGroup() {
        require(group.isGroupMember(groupId, msg.sender), "Not a group member");
        _;
    }

    function sendMessage(string calldata msgContent) external onlyGroup {
        // Process safe message from valid group sender
    }
}
