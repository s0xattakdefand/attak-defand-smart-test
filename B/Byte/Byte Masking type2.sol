contract ByteMasking {
    bytes1 public status;

    function setBits(bytes1 mask) public {
        status |= mask; // OR → sets bits
    }

    function clearBits(bytes1 mask) public {
        status &= ~mask; // AND NOT → clears bits
    }

    function toggleBits(bytes1 mask) public {
        status ^= mask; // XOR → toggles
    }
}
