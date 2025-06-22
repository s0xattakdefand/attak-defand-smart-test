mapping(uint160 => uint256) public maskUsage;

function trackMask(uint160 mask) external {
    maskUsage[mask]++;
}

function getDrift(uint160 m1, uint160 m2) external pure returns (uint8) {
    uint160 xor = m1 ^ m2;
    uint8 bits = 0;
    while (xor > 0) {
        bits += uint8(xor & 1);
        xor >>= 1;
    }
    return bits; // Number of flipped bits = drift
}
