pragma solidity ^0.8.21;

contract IPWhitelistProtection {
    address public admin;

    mapping(bytes32 => bool) public whitelistedIPs;
    event IPWhitelisted(string ip);
    event IPRevoked(string ip);
    event IPAccessed(string ip, address caller);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier onlyWhitelistedIP(string memory claimedIP) {
        bytes32 ipHash = keccak256(abi.encodePacked(claimedIP));
        require(whitelistedIPs[ipHash], "IP not authorized");
        _;
    }

    function addIP(string memory ip) external onlyAdmin {
        whitelistedIPs[keccak256(abi.encodePacked(ip))] = true;
        emit IPWhitelisted(ip);
    }

    function removeIP(string memory ip) external onlyAdmin {
        whitelistedIPs[keccak256(abi.encodePacked(ip))] = false;
        emit IPRevoked(ip);
    }

    function submitRequest(string memory claimedIP) external onlyWhitelistedIP(claimedIP) {
        // Handle request logic for IP-authorized users
        emit IPAccessed(claimedIP, msg.sender);
    }

    function isWhitelisted(string memory ip) external view returns (bool) {
        return whitelistedIPs[keccak256(abi.encodePacked(ip))];
    }
}
