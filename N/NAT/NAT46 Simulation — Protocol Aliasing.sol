contract ProtocolAliaser {
    mapping(bytes32 => address) public v6toV4;

    function register(bytes32 ipv6Alias, address v4Target) external {
        v6toV4[ipv6Alias] = v4Target;
    }

    function resolve(bytes32 ipv6Alias) external view returns (address) {
        return v6toV4[ipv6Alias];
    }
}
