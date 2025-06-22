contract NetmaskValidator {
    function validateMask(uint160 mask) external pure returns (bool) {
        // Mask must be continuous left-aligned bits (e.g., 1111..0000)
        bool seenZero = false;
        for (uint256 i = 159; i >= 0; i--) {
            bool bit = (mask & (1 << i)) != 0;
            if (!bit) seenZero = true;
            if (bit && seenZero) return false; // discontinuity
        }
        return true;
    }
}
