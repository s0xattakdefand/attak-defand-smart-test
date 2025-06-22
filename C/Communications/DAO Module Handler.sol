interface ISecureCommunicator {
    function verifyMessage(address, address, bytes calldata, uint256) external view returns (bool);
}

contract DAOHandler {
    ISecureCommunicator public comm;
    address public expectedSender;

    constructor(address communicator, address trustedSender) {
        comm = ISecureCommunicator(communicator);
        expectedSender = trustedSender;
    }

    function execute(bytes calldata payload, uint256 nonce) external {
        require(
            comm.verifyMessage(expectedSender, address(this), payload, nonce),
            "Invalid message"
        );

        // Decode and act on message
    }
}
