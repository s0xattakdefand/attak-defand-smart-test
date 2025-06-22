contract PortAddressTranslation {
    struct PortMap {
        address externalAddr;
        uint16 port;
    }

    mapping(address => PortMap) public pat;

    function assign(address internalAddr, address externalAddr, uint16 port) external {
        pat[internalAddr] = PortMap(externalAddr, port);
    }

    function resolve(address internalAddr) external view returns (address, uint16) {
        PortMap memory p = pat[internalAddr];
        return (p.externalAddr, p.port);
    }
}
