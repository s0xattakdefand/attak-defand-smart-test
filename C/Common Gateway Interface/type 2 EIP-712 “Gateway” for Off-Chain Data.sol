import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EIP712Gateway {
    using ECDSA for bytes32;

    address public gatewaySigner;

    event GatewayData(address indexed user, string data);

    constructor(address signer) {
        gatewaySigner = signer;
    }

    function gatewayProcessEIP712(string calldata data, bytes calldata signature) external {
        // recover
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, data, address(this)))
            .toEthSignedMessageHash();
        address recovered = msgHash.recover(signature);
        require(recovered == gatewaySigner, "Not authorized gateway input");

        emit GatewayData(msg.sender, data);
    }
}
