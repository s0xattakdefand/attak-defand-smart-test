contract SlotGuard {
    mapping(uint256 => bool) public allowedSlots;

    constructor() {
        allowedSlots[0] = true;
        allowedSlots[1] = true;
        // disallow slot 5
    }

    function verifySlot(uint256 slot) public view returns (bool) {
        return allowedSlots[slot];
    }
}
