interface ICompatibleRegistry {
    function isCompatible(uint32 domainId, address caller) external view returns (bool);
}

contract MessageRouter {
    ICompatibleRegistry public registry;

    constructor(address registryAddress) {
        registry = ICompatibleRegistry(registryAddress);
    }

    function receiveMessage(uint32 domainId, bytes calldata payload) external {
        require(registry.isCompatible(domainId, msg.sender), "Unauthorized domain");

        // Safe message handling
    }
}
