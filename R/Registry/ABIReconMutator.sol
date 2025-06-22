interface IABIReconLabelRegistry {
    function label(bytes4 selector, string calldata name, bool confirmed) external;
}

contract ABIReconMutator {
    IABIReconLabelRegistry public labelRegistry;

    constructor(address _registry) {
        labelRegistry = IABIReconLabelRegistry(_registry);
    }

    function mutateAndPush(address target, string calldata guess, string[] calldata suffixes) external {
        for (uint256 i = 0; i < suffixes.length; i++) {
            string memory full = string.concat(guess, suffixes[i], "()");
            bytes4 sel = bytes4(keccak256(bytes(full)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            labelRegistry.label(sel, full, ok);
        }
    }
}
