contract ABIReconMutator {
    mapping(bytes4 => string) public guesses;

    event SelectorGuessed(bytes4 indexed selector, string name);

    function guess(bytes4 selector, string calldata name) external {
        guesses[selector] = name;
        emit SelectorGuessed(selector, name);
    }
}
