pragma solidity ^0.8.21;

contract IPWhitelist {
    address public admin;

    mapping(bytes32 => bool) private whitelistedIPs;

    event IPWhitelisted(string ip);
    event IPRemoved(string ip);
    event PrivilegedActionPerformed(string ip, address executor);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier ipWhitelisted(string memory ip) {
        require(
            whitelistedIPs[keccak256(abi.encodePacked(ip))],
            "IP not whitelisted"
        );
        _;
    }

    function addIP(string memory ip) external onlyAdmin {
        bytes32 ipHash = keccak256(abi.encodePacked(ip));
        whitelistedIPs[ipHash] = true;
        emit IPWhitelisted(ip);
    }

    function removeIP(string memory ip) external onlyAdmin {
        bytes32 ipHash = keccak256(abi.encodePacked(ip));
        whitelistedIPs[ipHash] = false;
        emit IPRemoved(ip);
    }

    function privilegedAction(string memory callerIP) external ipWhitelisted(callerIP) {
        // Perform sensitive actions here
        emit PrivilegedActionPerformed(callerIP, msg.sender);
    }

    function isWhitelisted(string memory ip) external view returns (bool) {
        return whitelistedIPs[keccak256(abi.encodePacked(ip))];
    }
}
