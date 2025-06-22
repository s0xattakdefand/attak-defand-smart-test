interface IPoseidon {
    function poseidon(bytes32[2] calldata input) external pure returns (bytes32);
}

contract PoseidonHasher {
    IPoseidon public hasher;

    constructor(address _hasher) {
        hasher = IPoseidon(_hasher);
    }

    function hashPair(bytes32 a, bytes32 b) external view returns (bytes32) {
        return hasher.poseidon([a, b]);
    }
}
