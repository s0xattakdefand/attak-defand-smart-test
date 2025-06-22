contract HashChallenge {
    bytes32 public targetHash;

    constructor(string memory secret) {
        targetHash = keccak256(abi.encodePacked(secret));
    }

    function check(string memory input) public view returns (bool) {
        return keccak256(abi.encodePacked(input)) == targetHash;
    }
}
