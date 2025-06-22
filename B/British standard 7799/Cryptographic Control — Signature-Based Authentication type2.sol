import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BS7799CryptoControl {
    using ECDSA for bytes32;

    address public trustedSigner;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    function verifyAccess(bytes32 dataHash, bytes calldata sig) public view returns (bool) {
        return dataHash.toEthSignedMessageHash().recover(sig) == trustedSigner;
    }
}
