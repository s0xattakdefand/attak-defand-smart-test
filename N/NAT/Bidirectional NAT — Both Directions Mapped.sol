contract BiDirectionalNAT {
    mapping(address => address) public forward;
    mapping(address => address) public reverse;

    function map(address internalAddr, address externalAddr) external {
        forward[internalAddr] = externalAddr;
        reverse[externalAddr] = internalAddr;
    }

    function resolveInternal(address externalAddr) external view returns (address) {
        return reverse[externalAddr];
    }

    function resolveExternal(address internalAddr) external view returns (address) {
        return forward[internalAddr];
    }
}
