contract RARPAddressLabel {
    struct Label {
        string name;
        string tag;
        string role;
    }

    mapping(address => Label) public reverse;

    event AddressLabeled(address indexed who, string name, string tag, string role);

    function setLabel(address who, string calldata name, string calldata tag, string calldata role) external {
        reverse[who] = Label(name, tag, role);
        emit AddressLabeled(who, name, tag, role);
    }

    function get(address who) external view returns (Label memory) {
        return reverse[who];
    }
}
