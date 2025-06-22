function get(bytes32 key) external view validTTL(key) returns (bytes memory) {
    require(block.timestamp <= cache[key].expiresAt, "Expired");
    return cache[key].data;
}
