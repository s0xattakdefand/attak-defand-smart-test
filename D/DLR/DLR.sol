// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Lending Record (DLR) smart contract
contract DLR {
    // Struct to represent a loan
    struct Loan {
        address borrower;
        address lender;
        uint256 principal; // Loan amount in wei
        uint256 interest; // Interest amount in wei
        uint256 collateral; // Collateral amount in wei
        uint256 dueDate; // Timestamp when loan is due
        bool funded; // Whether the loan is funded
        bool repaid; // Whether the loan is repaid
        bool liquidated; // Whether collateral is liquidated
    }

    // Mapping to store loans by ID
    mapping(bytes32 => Loan) public loans;

    // Owner of the contract
    address public owner;

    // Event emitted when a loan is created
    event LoanCreated(bytes32 indexed loanId, address borrower, uint256 principal, uint256 interest, uint256 dueDate);

    // Event emitted when a loan is funded
    event LoanFunded(bytes32 indexed loanId, address lender, uint256 amount);

    // Event emitted when a loan is repaid
    event LoanRepaid(bytes32 indexed loanId, address borrower, uint256 amount);

    // Event emitted when collateral is liquidated
    event CollateralLiquidated(bytes32 indexed loanId, address borrower, uint256 amount);

    // Modifier to restrict actions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to check if loan exists and is not settled
    modifier onlyActiveLoan(bytes32 loanId) {
        require(loans[loanId].borrower != address(0), "Loan does not exist");
        require(!loans[loanId].repaid && !loans[loanId].liquidated, "Loan already settled");
        _;
    }

    // Constructor to initialize the owner
    constructor() {
        owner = msg.sender;
    }

    // Create a new loan request
    function createLoan(uint256 principal, uint256 interestRate, uint256 duration) 
        external 
        payable 
        returns (bytes32) 
    {
        require(principal > 0, "Principal must be greater than 0");
        require(interestRate > 0, "Interest rate must be greater than 0");
        require(duration > 0, "Duration must be greater than 0");
        require(msg.value > 0, "Collateral required");

        // Calculate interest (simplified: interestRate as a percentage of principal)
        uint256 interest = (principal * interestRate) / 100;
        bytes32 loanId = keccak256(abi.encodePacked(msg.sender, principal, block.timestamp));

        loans[loanId] = Loan({
            borrower: msg.sender,
            lender: address(0),
            principal: principal,
            interest: interest,
            collateral: msg.value,
            dueDate: block.timestamp + duration,
            funded: false,
            repaid: false,
            liquidated: false
        });

        emit LoanCreated(loanId, msg.sender, principal, interest, block.timestamp + duration);
        return loanId;
    }

    // Fund a loan
    function fundLoan(bytes32 loanId) 
        external 
        payable 
        onlyActiveLoan(loanId) 
    {
        Loan storage loan = loans[loanId];
        require(loan.lender == address(0), "Loan already funded");
        require(msg.value >= loan.principal, "Insufficient funds sent");
        require(msg.sender != loan.borrower, "Borrower cannot fund own loan");

        loan.lender = msg.sender;
        loan.funded = true;

        // Transfer principal to borrower
        payable(loan.borrower).transfer(loan.principal);

        // Refund excess funds to lender
        if (msg.value > loan.principal) {
            payable(msg.sender).transfer(msg.value - loan.principal);
        }

        emit LoanFunded(loanId, msg.sender, loan.principal);
    }

    // Repay a loan
    function repayLoan(bytes32 loanId) 
        external 
        payable 
        onlyActiveLoan(loanId) 
    {
        Loan storage loan = loans[loanId];
        require(msg.sender == loan.borrower, "Only borrower can repay");
        require(loan.funded, "Loan not funded");
        require(block.timestamp <= loan.dueDate, "Loan is past due");
        require(msg.value >= loan.principal + loan.interest, "Insufficient repayment amount");

        loan.repaid = true;

        // Transfer repayment to lender
        payable(loan.lender).transfer(loan.principal + loan.interest);

        // Return collateral to borrower
        payable(loan.borrower).transfer(loan.collateral);

        // Refund excess payment to borrower
        if (msg.value > loan.principal + loan.interest) {
            payable(msg.sender).transfer(msg.value - (loan.principal + loan.interest));
        }

        emit LoanRepaid(loanId, msg.sender, loan.principal + loan.interest);
    }

    // Liquidate collateral if loan is not repaid by due date
    function liquidateLoan(bytes32 loanId) 
        external 
        onlyActiveLoan(loanId) 
    {
        Loan storage loan = loans[loanId];
        require(loan.funded, "Loan not funded");
        require(block.timestamp > loan.dueDate, "Loan not yet due");
        require(msg.sender == loan.lender || msg.sender == owner, "Only lender or owner can liquidate");

        loan.liquidated = true;

        // Transfer collateral to lender
        payable(loan.lender).transfer(loan.collateral);

        emit CollateralLiquidated(loanId, loan.borrower, loan.collateral);
    }

    // Get loan details
    function getLoanDetails(bytes32 loanId) 
        external 
        view 
        returns (address, address, uint256, uint256, uint256, uint256, bool, bool, bool) 
    {
        Loan memory loan = loans[loanId];
        return (
            loan.borrower,
            loan.lender,
            loan.principal,
            loan.interest,
            loan.collateral,
            loan.dueDate,
            loan.funded,
            loan.repaid,
            loan.liquidated
        );
    }

    // Emergency withdraw by owner (in case funds are stuck)
    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Use createLoan or fundLoan to send ETH");
    }
}