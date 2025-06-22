import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract HostSignatureAuth {
    using ECDSA for bytes32;
    address public verifiedHost;

    constructor(address host) {
        verifiedHost = host;
    }

    function exec(bytes32 message, bytes calldata sig) external view returns (bool) {
        return message.toEthSignedMessageHash().recover(sig) == verifiedHost;
    }
}
