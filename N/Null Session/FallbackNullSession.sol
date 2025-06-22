contract FallbackNullSession {
    event FallbackAccess(address indexed caller, bytes data);

    fallback() external payable {
        emit FallbackAccess(msg.sender, msg.data); // ❌ No ACL check, open to fuzz/exploit
    }
}
