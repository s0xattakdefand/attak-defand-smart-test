contract NetmaskPoison {
    uint160 public baseMask;

    constructor(uint160 _mask) {
        baseMask = _mask;
    }

    function poisonMask(uint8 driftBits) public view returns (uint160) {
        uint160 poison = baseMask;
        poison ^= (uint160(1) << driftBits); // Flip one bit
        return poison;
    }
}
