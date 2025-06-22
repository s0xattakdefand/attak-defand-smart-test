contract EntropyABIEnhancer {
    struct LabelGuess {
        string name;
        uint8 entropy;
        bool confirmed;
    }

    mapping(bytes4 => LabelGuess) public abiGuess;

    function label(bytes4 selector, string calldata name, uint8 entropy, bool confirmed) external {
        abiGuess[selector] = LabelGuess(name, entropy, confirmed);
    }

    function get(bytes4 sel) external view returns (LabelGuess memory) {
        return abiGuess[sel];
    }
}
