mapping(address => bytes32) public storedHash;

function commitDataHash(bytes32 dataHash) external {
    storedHash[msg.sender] = dataHash;
}

function verifyData(bytes calldata originalData) external view returns (bool) {
    return keccak256(originalData) == storedHash[msg.sender];
}
