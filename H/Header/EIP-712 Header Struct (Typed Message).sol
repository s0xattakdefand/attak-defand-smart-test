import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EIP712HeaderVerify {
    using ECDSA for bytes32;

    bytes32 public constant DOMAIN_HASH = keccak256("EIP712Domain(string name)");

    struct Header {
        address from;
        uint256 nonce;
        uint256 deadline;
    }

    function verify(Header memory header, bytes calldata sig) external view returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_HASH,
            keccak256(abi.encode(header.from, header.nonce, header.deadline))
        ));
        return digest.recover(sig) == header.from;
    }
}
