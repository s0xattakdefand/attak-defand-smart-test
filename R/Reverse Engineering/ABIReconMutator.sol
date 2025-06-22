contract ABIReconMutator {
    mapping(bytes4 => string) public guesses;

    function guess(bytes4 selector, string calldata label) external {
        guesses[selector] = label;
    }

    function getGuess(bytes4 selector) external view returns (string memory) {
        return guesses[selector];
    }
}
