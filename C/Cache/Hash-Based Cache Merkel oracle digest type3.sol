contract HashCache {
    mapping(bytes32 => bytes32) public cached;

    function store(bytes32 key, bytes32 val) public {
        cached[key] = val;
    }

    function retrieve(bytes32 key) public view returns (bytes32) {
        require(cached[key] != bytes32(0), "Not cached");
        return cached[key];
    }
}
