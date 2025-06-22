// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * A secure approach:
 * - Accept data only if it has enough signatures from multiple cloud or node providers
 * - Minimizes single point of failure by requiring multiple signers
 */
contract MultiCloudOracle {
    using ECDSA for bytes32;

    // Mapping of authorized cloud addresses
    mapping(address => bool) public authorizedClouds;
    // Required threshold for valid signature count
    uint8 public minSignatures;

    // Example: aggregated price or data
    uint256 public aggregatedPrice;

    event PriceUpdated(uint256 price);

    constructor(address[] memory clouds, uint8 _minSignatures) {
        for (uint256 i = 0; i < clouds.length; i++) {
            authorizedClouds[clouds[i]] = true;
        }
        minSignatures = _minSignatures;
    }

    /**
     * @notice Updates the price if enough authorized clouds sign the new value.
     * @param newPrice The proposed new price
     * @param sigs The signatures from different clouds
     * @param signers The addresses corresponding to each signature
     */
    function updatePrice(
        uint256 newPrice,
        bytes[] calldata sigs,
        address[] calldata signers
    ) external {
        require(sigs.length == signers.length, "Mismatched arrays");

        // Recreate the message for the signers
        bytes32 msgHash = keccak256(
            abi.encodePacked(newPrice, address(this))
        ).toEthSignedMessageHash();

        uint8 validCount;

        for (uint256 i = 0; i < signers.length; i++) {
            if (authorizedClouds[signers[i]]) {
                address recovered = msgHash.recover(sigs[i]);
                if (recovered == signers[i]) {
                    validCount++;
                }
            }
        }

        require(validCount >= minSignatures, "Not enough valid signatures");

        aggregatedPrice = newPrice;
        emit PriceUpdated(newPrice);
    }
}
