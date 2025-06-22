interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract BrowserTokenApproval {
    function approveFromUI(IERC20 token, address spender, uint256 amount) external {
        require(amount <= 10 ether, "Too high"); // browser UI enforced limits
        token.approve(spender, amount);
    }
}
