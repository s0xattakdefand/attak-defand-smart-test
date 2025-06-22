pragma solidity ^0.8.21;

contract HashedIPWhitelist {
    address public admin;
    mapping(bytes32 => bool) private ipHashes;

    event IPAllowed(string ip);
    event IPRejected(string ip);
    event Accessed(address user, string ip);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier ipAllowed(string memory ip) {
        require(ipHashes[keccak256(abi.encodePacked(ip))], "IP not whitelisted");
        _;
    }

    function allowIP(string memory ip) external onlyAdmin {
        ipHashes[keccak256(abi.encodePacked(ip))] = true;
        emit IPAllowed(ip);
    }

    function rejectIP(string memory ip) external onlyAdmin {
        ipHashes[keccak256(abi.encodePacked(ip))] = false;
        emit IPRejected(ip);
    }

    function performAction(string memory ip) external ipAllowed(ip) {
        emit Accessed(msg.sender, ip);
        // Protected logic here
    }

    function checkIP(string memory ip) external view returns (bool) {
        return ipHashes[keccak256(abi.encodePacked(ip))];
    }
}
