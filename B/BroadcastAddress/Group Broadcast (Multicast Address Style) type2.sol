contract GroupBroadcaster {
    mapping(address => bool) public groupMember;

    event GroupBroadcast(address indexed sender, string topic, string message);

    constructor(address[] memory initialMembers) {
        for (uint i = 0; i < initialMembers.length; i++) {
            groupMember[initialMembers[i]] = true;
        }
    }

    modifier onlyGroup() {
        require(groupMember[msg.sender], "Not in group");
        _;
    }

    function updateGroup(address user, bool status) public onlyGroup {
        groupMember[user] = status;
    }

    function broadcastToGroup(string calldata topic, string calldata msgBody) public onlyGroup {
        emit GroupBroadcast(msg.sender, topic, msgBody);
    }
}
