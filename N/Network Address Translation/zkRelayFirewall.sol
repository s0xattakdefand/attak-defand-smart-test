interface IZKVerifier {
    function verify(bytes calldata proof, bytes32 input) external view returns (bool);
}

contract zkRelayFirewall {
    IZKVerifier public verifier;
    uint160 public subnetBase;
    uint160 public subnetMask;

    constructor(address _verifier, uint160 _base, uint160 _mask) {
        verifier = IZKVerifier(_verifier);
        subnetBase = _base;
        subnetMask = _mask;
    }

    function isInSubnet(address sender) internal view returns (bool) {
        return (uint160(sender) & subnetMask) == subnetBase;
    }

    function relay(
        address target,
        bytes calldata payload,
        bytes calldata proof,
        bytes32 input
    ) external {
        require(verifier.verify(proof, input), "ZK failed");
        require(isInSubnet(msg.sender), "Not in subnet");
        (bool ok, ) = target.call(payload);
        require(ok, "Call failed");
    }
}
