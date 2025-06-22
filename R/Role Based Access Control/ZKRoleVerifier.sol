interface IZKVerifier {
    function isValidRoot(uint256 root) external view returns (bool);
}

contract ZKRoleVerifier {
    mapping(address => uint256) public rootClaim;

    IZKVerifier public verifier;

    constructor(address zkVerifier) {
        verifier = IZKVerifier(zkVerifier);
    }

    function claimRole(address user, uint256 root) external {
        require(verifier.isValidRoot(root), "ZK Root invalid");
        rootClaim[user] = root;
    }
}
