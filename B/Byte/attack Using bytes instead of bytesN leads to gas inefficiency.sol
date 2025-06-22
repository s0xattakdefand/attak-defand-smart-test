contract InefficientBytes {
    bytes public flagData;

    function set(bytes calldata data) public {
        flagData = data; // ❌ expensive storage operation
    }
}
