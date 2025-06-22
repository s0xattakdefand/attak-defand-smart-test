pragma solidity ^0.8.21;

contract ISO20022Banking {
    struct PaymentInstruction {
        string currencyCode; // e.g., "USD", "EUR"
        address sender;
        address recipient;
        uint256 amount;
        uint256 timestamp;
    }

    event PaymentSent(PaymentInstruction payment);

    function sendPayment(string memory currency, address recipient, uint256 amount) external {
        require(amount > 0, "Invalid amount");

        PaymentInstruction memory pmt = PaymentInstruction({
            currencyCode: currency,
            sender: msg.sender,
            recipient: recipient,
            amount: amount,
            timestamp: block.timestamp
        });

        emit PaymentSent(pmt);
        // actual token transfer simulated here
    }
}
