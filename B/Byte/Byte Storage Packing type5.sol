contract PackedSlots {
    uint128 public a;
    uint128 public b; // both a & b fit in same slot

    function set(uint128 _a, uint128 _b) public {
        a = _a;
        b = _b;
    }
}
