interface IZKRouteVerifier {
    function verify(bytes calldata proof, bytes32 publicInput) external view returns (bool);
}

contract zkRoutedAccess {
    IZKRouteVerifier public verifier;
    mapping(address => bool) public knownRoutes;

    constructor(address _verifier) {
        verifier = IZKRouteVerifier(_verifier);
    }

    function approveRoute(address route) external {
        knownRoutes[route] = true;
    }

    function secureRouteCall(
        address route,
        bytes calldata payload,
        bytes calldata zkProof,
        bytes32 pubInput
    ) external {
        require(knownRoutes[route], "Untrusted route");
        require(verifier.verify(zkProof, pubInput), "Invalid zk proof");

        (bool ok, ) = route.call(payload);
        require(ok, "Secure route failed");
    }
}
