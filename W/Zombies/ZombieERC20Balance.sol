interface IERC20 {
    function balanceOf(address user) external view returns (uint256);
}

contract ZombieERC20Balance {
    function isDust(address user, address token) external view returns (bool) {
        uint256 bal = IERC20(token).balanceOf(user);
        return user.code.length == 0 && bal > 0;
    }
}
