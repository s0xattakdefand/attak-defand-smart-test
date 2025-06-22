contract OpcodeScanner {
    mapping(bytes4 => bool) public blacklisted;

    constructor() {
        blacklisted[bytes4(keccak256("selfDestruct()"))] = true;
        blacklisted[bytes4(0xdeaddead)] = true; // example
    }

    function isSafeSelector(bytes calldata payload) public view returns (bool) {
        if (payload.length < 4) return false;
        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }
        return !blacklisted[selector];
    }
}
