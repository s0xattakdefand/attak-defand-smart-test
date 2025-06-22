contract SafeCacheRegistry is Ownable {
    struct Entry {
        bytes data;
        uint256 expiresAt;
    }

    mapping(bytes32 => Entry) public cache;
    mapping(address => uint256) public writes;
    uint256 public writeLimit = 5;
    uint256 public ttl = 10 minutes;
    uint256 public writeFee = 0.005 ether;

    event Cached(bytes32 indexed key, address indexed user, bytes data);

    modifier antiCramming() {
        require(writes[msg.sender] < writeLimit, "Cramming blocked");
        _;
    }

    function write(bytes32 key, bytes calldata data) external payable antiCramming {
        require(msg.value >= writeFee, "Write fee too low");

        cache[key] = Entry({data: data, expiresAt: block.timestamp + ttl});
        writes[msg.sender]++;
        emit Cached(key, msg.sender, data);
    }

    function read(bytes32 key) external view returns (bytes memory) {
        require(block.timestamp <= cache[key].expiresAt, "Expired");
        return cache[key].data;
    }
}
