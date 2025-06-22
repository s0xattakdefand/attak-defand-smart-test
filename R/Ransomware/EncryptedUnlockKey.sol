contract EncryptedUnlockKey {
    bytes32 private keyHash;
    bool public unlocked;

    constructor(bytes32 _hash) {
        keyHash = _hash;
    }

    function unlock(bytes32 key) external {
        require(keccak256(abi.encodePacked(key)) == keyHash, "Wrong key");
        unlocked = true;
    }
}
