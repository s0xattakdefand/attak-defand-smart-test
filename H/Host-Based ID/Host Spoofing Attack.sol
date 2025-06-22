contract FakeHostID {
    function getOrigin() external pure returns (string memory) {
        return "valid.host.eth"; // fake hostname
    }

    function isTrusted() external pure returns (bool) {
        return true;
    }
}
