// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ReverseSOAPAttackDefense - Attack and Defense Simulation for Reverse SOAP (Response Injection) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure External Response Handling (No Signature or Source Verification)
contract InsecureReverseSOAP {
    uint256 public latestPrice;

    event PriceUpdated(uint256 newPrice);

    function updatePrice(uint256 price) external {
        // 🔥 Anyone can push any fake price!
        latestPrice = price;
        emit PriceUpdated(price);
    }
}

/// @notice Secure External Response Handling (Signature Verification, Request-Response Binding)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureReverseSOAP is Ownable {
    using ECDSA for bytes32;

    address public trustedOracle;
    mapping(bytes32 => bool) public usedRequestIds;
    uint256 public latestPrice;

    event PriceUpdated(uint256 newPrice, bytes32 requestId);

    constructor(address _trustedOracle) {
        trustedOracle = _trustedOracle;
    }

    struct OracleResponse {
        bytes32 requestId;
        uint256 price;
        uint256 timestamp;
        bytes signature;
    }

    function submitOracleResponse(OracleResponse calldata response) external {
        require(!usedRequestIds[response.requestId], "Request ID already used");
        require(response.timestamp <= block.timestamp + 2 minutes, "Stale response");

        bytes32 messageHash = keccak256(abi.encodePacked(
            response.requestId,
            response.price,
            response.timestamp,
            address(this),
            block.chainid
        ));
        address signer = messageHash.toEthSignedMessageHash().recover(response.signature);

        require(signer == trustedOracle, "Invalid oracle signature");

        usedRequestIds[response.requestId] = true;
        latestPrice = response.price;

        emit PriceUpdated(response.price, response.requestId);
    }

    function updateTrustedOracle(address newOracle) external onlyOwner {
        trustedOracle = newOracle;
    }
}

/// @notice Attack contract simulating response injection without verification
contract SOAPIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakePrice(uint256 fakePrice) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updatePrice(uint256)", fakePrice)
        );
    }
}
