import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ByteSignatureVerify {
    using ECDSA for bytes32;

    address public signer;

    constructor(address _signer) {
        signer = _signer;
    }

    function verify(bytes calldata message, bytes calldata sig) external view returns (bool) {
        bytes32 hash = keccak256(message).toEthSignedMessageHash();
        return hash.recover(sig) == signer;
    }
}
