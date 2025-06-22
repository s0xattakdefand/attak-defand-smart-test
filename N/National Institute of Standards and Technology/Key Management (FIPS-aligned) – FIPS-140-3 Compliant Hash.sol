contract NISTHash {
    function sha256Hash(bytes memory input) external pure returns (bytes32) {
        return sha256(input); // FIPS-compliant hash
    }
}
