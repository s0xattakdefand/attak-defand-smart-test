contract ProxySlotRecon {
    function detectEIP1967(address proxy) external view returns (address impl) {
        bytes32 slot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        assembly {
            impl := sload(slot)
        }
    }
}
