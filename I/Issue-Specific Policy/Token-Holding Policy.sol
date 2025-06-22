pragma solidity ^0.8.21;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract TokenGatePolicy {
    address public token;
    uint256 public minRequired;

    constructor(address _token, uint256 _min) {
        token = _token;
        minRequired = _min;
    }

    modifier onlyTokenHolders() {
        require(IERC20(token).balanceOf(msg.sender) >= minRequired, "Insufficient tokens");
        _;
    }

    function gatedFunction() external onlyTokenHolders {
        // Logic only token holders can access
    }
}
