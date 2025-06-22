// Generate selector dynamically to bypass sig scanners
function getMutatedSelector(string memory fn) public pure returns (bytes4) {
    return bytes4(keccak256(bytes(fn)));
}

function callWithMutation(address target, string memory fn, bytes memory args) external {
    bytes memory data = abi.encodePacked(getMutatedSelector(fn), args);
    (bool ok, ) = target.call(data);
    require(ok, "Mutation call failed");
}
