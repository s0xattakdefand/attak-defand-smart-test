contract OctetOverflowAttack {
    event Triggered(uint8 indexed attackerOctet, uint256 manipulatedValue);

    function octetInject(uint8 octet) external {
        uint256 targetValue = 0xFFFFFF00 + octet;
        emit Triggered(octet, targetValue); // Drift into overflow range
    }
}
