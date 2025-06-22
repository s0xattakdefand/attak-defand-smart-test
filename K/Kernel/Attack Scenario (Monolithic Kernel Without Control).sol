pragma solidity ^0.8.21;

contract UnsafeKernel {
    address public owner;

    function update(address newOwner) external {
        owner = newOwner; // No access control at all
    }
}
