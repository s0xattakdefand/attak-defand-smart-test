contract EncryptedVault {
    bytes32 private secretHash;
    address public target;
    bool public unlocked;

    event VaultUnlocked(address indexed by);

    constructor(bytes32 _secretHash, address _target) {
        secretHash = _secretHash;
        target = _target;
    }

    function unlock(bytes32 preimage) external {
        require(keccak256(abi.encodePacked(preimage)) == secretHash, "Wrong key");
        unlocked = true;
        emit VaultUnlocked(msg.sender);
    }
}
