// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ParityBitAttackDefense - Attack and Defense Simulation for Parity Bit Integrity Checks in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Parity Bit Handling (No Real Validation, Accepts Forged Data)
contract InsecureParityBit {
    event DataAccepted(address indexed sender, uint256 data, uint8 parityBit);

    function submitData(uint256 data, uint8 parityBit) external {
        // 🔥 No actual check of parity bit vs data!
        emit DataAccepted(msg.sender, data, parityBit);
    }
}

/// @notice Secure Parity Bit Handling (Actual Validation, Reject Forged Data)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureParityBit is Ownable {
    event DataAccepted(address indexed sender, uint256 data, uint8 expectedParityBit);

    function submitData(uint256 data, uint8 parityBit) external {
        require(parityBit == computeParityBit(data), "Invalid parity bit");
        emit DataAccepted(msg.sender, data, parityBit);
    }

    /// @notice Compute the parity bit: 0 for even, 1 for odd number of set bits
    function computeParityBit(uint256 data) public pure returns (uint8) {
        uint256 count;
        while (data != 0) {
            count += data & 1;
            data >>= 1;
        }
        return uint8(count % 2);
    }
}

/// @notice Attack contract simulating fake parity bit submission
contract ParityBitIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeSubmit(uint256 data, uint8 forgedParity) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitData(uint256,uint8)", data, forgedParity)
        );
    }
}
