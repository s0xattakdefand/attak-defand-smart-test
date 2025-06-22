interface IZKVerifier {
    function verifyProof(bytes calldata proof, bytes calldata input) external view returns (bool);
}

contract DAOIdentityChecker {
    CommonServiceProviderRegistry public registry;

    constructor(address _registry) {
        registry = CommonServiceProviderRegistry(_registry);
    }

    function verifyMembership(address verifier, bytes calldata proof, bytes calldata input) external view returns (bool) {
        require(registry.isActive(verifier), "Verifier not trusted");
        return IZKVerifier(verifier).verifyProof(proof, input);
    }
}
