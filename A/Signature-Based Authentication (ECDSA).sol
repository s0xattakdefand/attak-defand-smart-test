import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AuthBySignature {
    using ECDSA for bytes32;

    address public trustedSigner;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    function verifySignedAction(
        address user,
        uint256 nonce,
        bytes memory signature
    ) public view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(user, nonce));
        bytes32 message = hash.toEthSignedMessageHash();
        return message.recover(signature) == trustedSigner;
    }
}
