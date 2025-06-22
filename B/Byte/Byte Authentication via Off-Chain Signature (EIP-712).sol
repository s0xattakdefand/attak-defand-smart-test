import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ByteAuthEIP712 {
    using ECDSA for bytes32;

    mapping(address => bytes1) public roles;
    mapping(address => uint256) public nonces;
    address public verifier;

    constructor(address _verifier) {
        verifier = _verifier;
    }

    function authWithSig(bytes calldata sig, uint8 roleBit) external {
        uint256 nonce = nonces[msg.sender]++;
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, roleBit, nonce));
        bytes32 ethHash = hash.toEthSignedMessageHash();
        require(ethHash.recover(sig) == verifier, "Invalid signature");

        roles[msg.sender] |= bytes1(uint8(1 << roleBit));
    }
}
