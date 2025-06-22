pragma solidity ^0.8.21;

contract OpenMint {
    uint256 public totalSupply;

    function mint(uint256 amount) external {
        totalSupply += amount; // Unrestricted access!
    }
}
