pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract OracleSignedIPAuth {
    using ECDSA for bytes32;

    address public trustedOracle;

    event VerifiedIP(address user, string ip);

    constructor(address _oracle) {
        trustedOracle = _oracle;
    }

    function verifyIP(string memory ip, uint256 timestamp, bytes memory signature) external {
        require(block.timestamp <= timestamp + 2 minutes, "IP proof expired");

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, ip, timestamp));
        bytes32 ethSigned = messageHash.toEthSignedMessageHash();

        require(ethSigned.recover(signature) == trustedOracle, "Invalid oracle signature");

        emit VerifiedIP(msg.sender, ip);
        // Grant access or log event
    }
}
