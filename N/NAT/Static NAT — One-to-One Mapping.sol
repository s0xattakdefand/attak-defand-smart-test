contract StaticNAT {
    mapping(address => address) public staticMap; // internal → external

    function setMapping(address internalAddr, address externalAddr) external {
        staticMap[internalAddr] = externalAddr;
    }

    function resolve(address internalAddr) external view returns (address) {
        return staticMap[internalAddr];
    }
}
