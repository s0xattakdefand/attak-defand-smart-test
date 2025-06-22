// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AssociatedDataVerifier {
    event DataProcessed(address indexed user, bytes data, uint256 bitLength);

    /// @notice Verify the bit-length of associated data explicitly
    function processAssociatedData(bytes calldata associatedData, uint256 expectedBitLength) external returns (bool) {
        require(isValidBitLength(associatedData, expectedBitLength), "Invalid associated data bit length");

        // Further secure processing logic goes here

        emit DataProcessed(msg.sender, associatedData, expectedBitLength);
        return true;
    }

    /// @notice Dynamically checks if data matches expected bit length
    function isValidBitLength(bytes calldata data, uint256 expectedBitLength) public pure returns (bool) {
        uint256 dataBitLength = data.length * 8;
        return dataBitLength == expectedBitLength;
    }

    /// @notice Compute bit length dynamically
    function getBitLength(bytes calldata data) external pure returns (uint256) {
        return data.length * 8;
    }
}
