contract PinLock {
    uint256 private pinHash;
    mapping(address => uint8) public failedAttempts;

    constructor(uint256 pin) {
        pinHash = uint256(keccak256(abi.encodePacked(pin)));
    }

    function unlock(uint256 pin) public returns (bool) {
        require(failedAttempts[msg.sender] < 3, "Too many attempts");

        if (uint256(keccak256(abi.encodePacked(pin))) == pinHash) {
            return true;
        } else {
            failedAttempts[msg.sender]++;
            return false;
        }
    }
}
