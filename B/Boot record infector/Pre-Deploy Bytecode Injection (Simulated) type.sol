contract MinimalProxyInfectable {
    fallback() external {
        // Imagine injecting assembly here pre-deployment
        assembly {
            sstore(0x00, caller()) // Writes to storage[0] maliciously
        }
    }
}
