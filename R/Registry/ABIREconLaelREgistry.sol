contract ABIReconLabelRegistry {
    struct ABILabel {
        bytes4 selector;
        string guess;
        bool confirmed;
    }

    mapping(bytes4 => ABILabel) public labels;

    event Labeled(bytes4 selector, string name, bool confirmed);

    function label(bytes4 selector, string calldata guess, bool confirmed) external {
        labels[selector] = ABILabel(selector, guess, confirmed);
        emit Labeled(selector, guess, confirmed);
    }

    function get(bytes4 selector) external view returns (ABILabel memory) {
        return labels[selector];
    }
}
