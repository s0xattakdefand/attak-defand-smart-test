contract NPCDetector {
    event NPCFound(string field, uint8 index, bytes1 character);

    function scan(bytes calldata input, string calldata field) external {
        for (uint256 i = 0; i < input.length; i++) {
            if (uint8(input[i]) < 0x20 || uint8(input[i]) == 0x7F) {
                emit NPCFound(field, uint8(i), input[i]);
            }
        }
    }
}
