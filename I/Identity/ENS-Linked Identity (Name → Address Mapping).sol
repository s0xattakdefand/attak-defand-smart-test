interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
}

interface IENSResolver {
    function addr(bytes32 node) external view returns (address);
}

contract ENSIdentity {
    IENSRegistry public ens;

    constructor(address _ens) {
        ens = IENSRegistry(_ens);
    }

    function resolveENS(string memory name) external view returns (address) {
        bytes32 node = keccak256(abi.encodePacked(name)); // Simplified
        address resolverAddr = ens.resolver(node);
        return IENSResolver(resolverAddr).addr(node);
    }
}
