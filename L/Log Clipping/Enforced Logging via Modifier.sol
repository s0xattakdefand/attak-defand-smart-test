pragma solidity ^0.8.21;

contract LogSecured {
    event Withdrawal(address indexed user, uint256 amount);

    modifier logsWithdrawal(uint256 amount) {
        _;
        emit Withdrawal(msg.sender, amount);
    }

    function withdraw(uint256 amount) external logsWithdrawal(amount) {
        payable(msg.sender).transfer(amount);
    }
}
