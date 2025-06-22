contract SubnetAccessRegistry {
    struct Subnet {
        uint160 mask;
        uint160 base;
    }

    mapping(address => Subnet) public permitted;

    function register(address user, uint160 mask, uint160 base) external {
        permitted[user] = Subnet(mask, base);
    }

    function isInSubnet(address user, address query) external view returns (bool) {
        Subnet memory s = permitted[user];
        return (uint160(query) & s.mask) == s.base;
    }
}
