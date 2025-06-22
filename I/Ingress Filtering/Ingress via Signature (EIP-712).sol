import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignedIngressFilter {
    using ECDSA for bytes32;

    function verify(bytes calldata sig) external view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender)).toEthSignedMessageHash();
        return hash.recover(sig) == msg.sender;
    }
}
