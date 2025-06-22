contract AddressLabelResolver {
    struct Label {
        string name;
        string role;
        string tag;
    }

    mapping(address => Label) public labels;

    function register(address who, string calldata name, string calldata role, string calldata tag) external {
        labels[who] = Label(name, role, tag);
    }

    function reverse(address who) external view returns (Label memory) {
        return labels[who];
    }
}
