contract RARPSelectorName {
    mapping(bytes4 => string) public functionName;

    event SelectorNamed(bytes4 indexed sel, string name);

    function name(bytes4 sel, string calldata guess) external {
        functionName[sel] = guess;
        emit SelectorNamed(sel, guess);
    }
}
