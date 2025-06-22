import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EIP712Client {
    using ECDSA for bytes32;

    address public signer;

    event ClientAction(address indexed client);

    constructor(address _signer) {
        signer = _signer;
    }

    function processOffChainSig(
        bytes32 dataHash,
        bytes calldata signature
    ) external {
        // Check signature from recognized signer => identifies a legit client
        bytes32 ethHash = dataHash.toEthSignedMessageHash();
        address recovered = ethHash.recover(signature);
        require(recovered == signer, "Not recognized client signer");
        
        emit ClientAction(msg.sender);
    }
}
