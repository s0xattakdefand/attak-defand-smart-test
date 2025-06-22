contract NPCMetadataPoison {
    event PoisonedMetadata(string input);

    function poisonWithZeroWidth(string calldata label) external view returns (string memory) {
        string memory zwsp = unicode"\u200b";
        string memory poisoned = string(abi.encodePacked(label, zwsp, "🧨"));
        emit PoisonedMetadata(poisoned);
        return poisoned;
    }
}
