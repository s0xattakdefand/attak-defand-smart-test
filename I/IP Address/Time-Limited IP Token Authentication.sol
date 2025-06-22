pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract IPTimeTokenAuth {
    using ECDSA for bytes32;

    address public oracle;

    constructor(address _oracle) {
        oracle = _oracle;
    }

    function validateAccessToken(
        string memory ip,
        uint256 expiresAt,
        bytes memory signature
    ) external view returns (bool) {
        require(block.timestamp < expiresAt, "Token expired");

        bytes32 digest = keccak256(abi.encodePacked(msg.sender, ip, expiresAt));
        bytes32 ethDigest = digest.toEthSignedMessageHash();

        return ethDigest.recover(signature) == oracle;
    }
}
