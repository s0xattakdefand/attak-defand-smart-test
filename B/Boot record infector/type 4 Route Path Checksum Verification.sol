contract RouteChecksumVerifier {
    function verifyRouteChecksum(string calldata route, bytes32 expectedHash) public pure returns (bool) {
        return keccak256(abi.encodePacked(route)) == expectedHash;
    }
}
