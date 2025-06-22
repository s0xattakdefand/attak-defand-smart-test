// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PointToPointAttackDefense - Attack and Defense Simulation for Point-to-Point (P2P/PtP) communication in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Point-to-Point transfer (No Authentication, No Nonce, No Timeout)
contract InsecurePointToPoint {
    event PtPTransfer(address indexed from, address indexed to, uint256 amount);

    function send(address payable to) external payable {
        require(msg.value > 0, "Send ETH required");
        to.transfer(msg.value);
        emit PtPTransfer(msg.sender, to, msg.value);
    }
}

/// @notice Secure Point-to-Point transfer with Nonce, Signature, and Expiry enforcement
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecurePointToPoint is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedSessions;
    uint256 public constant MAX_SESSION_LIFETIME = 10 minutes;

    event PtPSessionSettled(address indexed from, address indexed to, uint256 amount, bytes32 sessionHash);

    function settlePointToPoint(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 sessionStartBlock,
        bytes calldata signature
    ) external payable {
        require(block.number <= sessionStartBlock + (MAX_SESSION_LIFETIME / 12), "Session expired");
        require(msg.value == amount, "Incorrect amount sent");

        bytes32 sessionHash = keccak256(abi.encodePacked(from, to, amount, nonce, sessionStartBlock, address(this), block.chainid));
        require(!usedSessions[sessionHash], "Session already used");

        address signer = sessionHash.toEthSignedMessageHash().recover(signature);
        require(signer == from, "Invalid session signature");

        usedSessions[sessionHash] = true;
        payable(to).transfer(amount);
        emit PtPSessionSettled(from, to, amount, sessionHash);
    }

    receive() external payable {}
}

/// @notice Attack contract trying to replay or inject PtP sessions
contract PtPIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replaySession(address payable fakeTo) external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("send(address)", fakeTo)
        );
    }
}
