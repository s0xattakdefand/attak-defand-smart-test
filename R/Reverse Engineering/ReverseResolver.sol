contract ReverseResolver {
    struct Meta {
        string label;
        string role;
        string tag;
    }

    mapping(address => Meta) public metadata;

    function label(address who, string calldata label, string calldata role, string calldata tag) external {
        metadata[who] = Meta(label, role, tag);
    }

    function resolve(address who) external view returns (Meta memory) {
        return metadata[who];
    }
}
