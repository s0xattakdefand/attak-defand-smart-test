interface IZKAuth {
    function verify(bytes calldata proof, bytes32 input) external view returns (bool);
}

contract zkNATProxy {
    IZKAuth public zkVerifier;

    constructor(address _verifier) {
        zkVerifier = IZKAuth(_verifier);
    }

    function zkRelay(bytes calldata proof, bytes32 input, address to, bytes calldata data) external {
        require(zkVerifier.verify(proof, input), "zk NAT auth failed");
        (bool ok, ) = to.call(data);
        require(ok, "Call failed");
    }
}
