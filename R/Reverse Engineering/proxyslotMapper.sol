contract ProxySlotMapper {
    function getImplementationSlot() public pure returns (bytes32) {
        return bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    }

    function get(address proxy) external view returns (address impl) {
        bytes32 slot = getImplementationSlot();
        assembly { impl := sload(slot) }
    }
}
