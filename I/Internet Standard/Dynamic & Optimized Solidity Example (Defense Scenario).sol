pragma solidity ^0.8.21;

contract StandardizedOracle {
    address public admin;
    uint8 public constant SECURE_VERSION = 2;

    uint256 public currentPrice;
    mapping(address => bool) public authorizedUpdaters;

    event PriceUpdated(uint256 price, uint8 version, address updater);

    constructor() {
        admin = msg.sender;
        authorizedUpdaters[admin] = true;
    }

    modifier onlyAuthorized() {
        require(authorizedUpdaters[msg.sender], "Unauthorized updater");
        _;
    }

    modifier enforceSecureVersion(uint8 version) {
        require(version >= SECURE_VERSION, "Insecure protocol version");
        _;
    }

    function authorizeUpdater(address updater, bool status) external {
        require(msg.sender == admin, "Only admin");
        authorizedUpdaters[updater] = status;
    }

    function updatePrice(uint256 price, uint8 version)
        external
        onlyAuthorized
        enforceSecureVersion(version)
    {
        currentPrice = price;
        emit PriceUpdated(price, version, msg.sender);
    }
}
