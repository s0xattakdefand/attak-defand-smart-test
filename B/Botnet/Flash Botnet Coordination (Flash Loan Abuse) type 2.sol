interface IFlashLoan {
    function executeFlashLoan(uint256 amount) external;
}

contract FlashBotnet {
    IFlashLoan public loanProvider;

    constructor(address _provider) {
        loanProvider = IFlashLoan(_provider);
    }

    function triggerAttack(uint256 amount) public {
        loanProvider.executeFlashLoan(amount);
    }
}
