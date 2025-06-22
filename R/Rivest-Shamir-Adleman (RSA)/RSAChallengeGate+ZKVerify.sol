interface IZKRegistry {
    function isValidRoot(uint256 root) external view returns (bool);
}

contract RSA_ZKVerifier {
    struct PubKey {
        uint256 e;
        uint256 n;
        string role;
    }

    mapping(address => PubKey) public keys;
    mapping(bytes32 => bool) public used;

    IZKRegistry public semaphore;

    event VerifiedZK(address signer, string role, uint256 zkRoot, bytes32 payloadHash);

    constructor(address _semaphore) {
        semaphore = IZKRegistry(_semaphore);
    }

    function register(uint256 e, uint256 n, string calldata role) external {
        keys[msg.sender] = PubKey(e, n, role);
    }

    function verifyZKPayload(
        address signer,
        bytes32 payloadHash,
        uint256 sig,
        uint256 zkRoot
    ) external returns (string memory role) {
        require(!used[payloadHash], "Replay");
        require(semaphore.isValidRoot(zkRoot), "ZK root not registered");

        PubKey memory k = keys[signer];
        require(modExp(sig, k.e, k.n) == uint256(payloadHash), "Invalid RSA");
        used[payloadHash] = true;

        emit VerifiedZK(signer, k.role, zkRoot, payloadHash);
        return k.role;
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 r) {
        r = 1;
        for (; exp > 0; exp >>= 1) {
            if (exp & 1 != 0) r = mulmod(r, base, mod);
            base = mulmod(base, base, mod);
        }
    }
}
