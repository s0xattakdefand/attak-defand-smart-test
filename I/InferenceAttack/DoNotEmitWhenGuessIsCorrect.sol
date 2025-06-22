contract SilentVerifier {
    uint256 private key = 1234;

    function verify(uint256 input) external view returns (bool) {
        return input == key; // but no event/log
    }
}
