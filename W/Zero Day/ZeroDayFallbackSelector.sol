contract ZeroDayFallbackSelector {
    mapping(bytes4 => bool) public seenSelectors;
    event UnknownSelector(bytes4 selector);

    fallback() external {
        bytes4 sel;
        assembly { sel := calldataload(0) }

        if (!seenSelectors[sel]) {
            seenSelectors[sel] = true;
            emit UnknownSelector(sel);
        }

        // 🧨 backdoor or unexpected logic may exist here
    }
}
