// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PeerToPeerAttackDefense - Attack and Defense Simulation for Peer-to-Peer (P2P) interactions in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure P2P exchange (No atomicity, No fairness guarantees)
contract InsecureP2P {
    event AssetSent(address indexed from, address indexed to, uint256 amount);

    function sendAsset(address payable to) external payable {
        // 🔥 No guarantee of reciprocation!
        require(msg.value > 0, "Send ETH");
        to.transfer(msg.value);
        emit AssetSent(msg.sender, to, msg.value);
    }
}

/// @notice Secure P2P exchange with full atomic settlement
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureP2P is Ownable {
    using ECDSA for bytes32;

    struct Offer {
        address from;
        address to;
        uint256 offeredAmount;
        uint256 requestedAmount;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(bytes32 => bool) public usedOffers;

    event P2PSettled(address indexed from, address indexed to, uint256 offeredAmount, uint256 requestedAmount);

    function acceptOffer(
        address from,
        address to,
        uint256 offeredAmount,
        uint256 requestedAmount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable {
        require(block.timestamp <= deadline, "Offer expired");
        require(msg.value == requestedAmount, "Incorrect requested payment");

        bytes32 offerHash = keccak256(abi.encodePacked(from, to, offeredAmount, requestedAmount, nonce, deadline, address(this), block.chainid));
        require(!usedOffers[offerHash], "Offer already used");

        address signer = offerHash.toEthSignedMessageHash().recover(signature);
        require(signer == from, "Invalid offer signature");

        usedOffers[offerHash] = true;

        // Atomic settlement
        payable(to).transfer(requestedAmount);   // Buyer gets their requested asset
        payable(msg.sender).transfer(offeredAmount); // Seller gets their offered asset

        emit P2PSettled(from, to, offeredAmount, requestedAmount);
    }

    receive() external payable {} // Accept ETH to allow escrow.
}

/// @notice Attack contract trying to replay P2P offers
contract P2PIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replaySend(address payable victim) external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("sendAsset(address)", victim)
        );
    }
}
