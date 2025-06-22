interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

contract BrowserWalletVerifier {
    bytes4 constant MAGICVALUE = 0x1626ba7e;

    function verifyWallet(address wallet, bytes32 hash, bytes calldata sig) public view returns (bool) {
        return IERC1271(wallet).isValidSignature(hash, sig) == MAGICVALUE;
    }
}
