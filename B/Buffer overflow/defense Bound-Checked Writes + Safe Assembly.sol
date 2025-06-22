contract BufferOverflowSafe {
    uint256[] public data;

    constructor() {
        data.push(0); // init with 1 element
    }

    function safeSet(uint256 index, uint256 value) public {
        require(index < data.length, "Out of bounds");
        data[index] = value;
    }

    function safePush(uint256 value) public {
        data.push(value);
    }

    function get(uint256 index) public view returns (uint256) {
        require(index < data.length, "Out of bounds");
        return data[index];
    }
}
