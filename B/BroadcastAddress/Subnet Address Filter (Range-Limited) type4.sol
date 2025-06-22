contract SubnetFilteredBroadcast {
    address public admin;
    uint160 public min;
    uint160 public max;

    event SubnetBroadcast(address indexed sender, string message);

    constructor(uint160 _min, uint160 _max) {
        admin = msg.sender;
        min = _min;
        max = _max;
    }

    modifier onlySubnet() {
        require(uint160(msg.sender) >= min && uint160(msg.sender) <= max, "Not in subnet");
        _;
    }

    function broadcast(string calldata message) public onlySubnet {
        emit SubnetBroadcast(msg.sender, message);
    }
}
