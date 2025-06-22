// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BufferOverflowAttackDefense - Buffer Overflow Attack and Defense Simulation in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Dynamic Buffer Management (No bounds checks)
contract InsecureBuffer {
    uint256[] public numbers;
    address public owner;

    event NumberPushed(uint256 number);
    event OwnershipTransferred(address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    function pushNumberUnchecked(uint256 number) external {
        // 🔥 No bounds checking on array push
        numbers.push(number);
        emit NumberPushed(number);
    }

    function overwriteOwner(uint256 fakeOwnerAddress) external {
        // 🔥 Unsafe manual overwrite beyond bounds
        assembly {
            sstore(add(numbers.slot, 1), fakeOwnerAddress)
        }
        emit OwnershipTransferred(address(uint160(fakeOwnerAddress)));
    }
}

/// @notice Secure Dynamic Buffer Management with Bounds Checking and Storage Protection
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBuffer is Ownable {
    uint256[] public numbers;
    uint256 public constant MAX_ARRAY_SIZE = 1000;

    event NumberPushed(uint256 number);

    function pushNumber(uint256 number) external {
        require(numbers.length < MAX_ARRAY_SIZE, "Max buffer size exceeded");
        numbers.push(number);
        emit NumberPushed(number);
    }

    function getNumber(uint256 index) external view returns (uint256) {
        require(index < numbers.length, "Index out of bounds");
        return numbers[index];
    }
}

/// @notice Attack contract trying to overflow buffers
contract BufferIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function attackOverwriteOwner(uint256 fakeOwner) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("overwriteOwner(uint256)", fakeOwner)
        );
    }
}
