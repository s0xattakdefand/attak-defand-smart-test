pragma solidity ^0.8.21;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
}

contract SafeTokenSpender {
    IERC20 public token;
    address public spender;
    uint256 public constant MAX_APPROVAL = 1_000 ether;

    constructor(IERC20 _token, address _spender) {
        token = _token;
        spender = _spender;
    }

    function approveWithLimit() external {
        token.approve(spender, MAX_APPROVAL);
    }
}
