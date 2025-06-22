contract ZombieProxyReanimator {
    event ProxyRewired(address proxy, address newLogic);

    function rewire(address proxy, address newLogic) external {
        bytes32 slot = keccak256("eip1967.proxy.implementation") - 1;
        assembly {
            sstore(slot, newLogic)
        }
        emit ProxyRewired(proxy, newLogic);
    }
}
