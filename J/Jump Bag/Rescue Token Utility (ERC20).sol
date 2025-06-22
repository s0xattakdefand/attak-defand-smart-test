pragma solidity ^0.8.21;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RescueERC20 {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function rescue(address token, address to, uint256 amount) external {
        require(msg.sender == admin, "Not admin");
        IERC20(token).transfer(to, amount);
    }
}
