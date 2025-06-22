contract FallbackEntry {
    event Access(address caller, bytes data);

    fallback() external {
        emit Access(msg.sender, msg.data); // ❌ Open for fuzzing, abuse, execution
    }
}
