library ADAL {
    function getAuthHash(address user, string memory scope, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, scope, nonce));
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return ecrecover(ethSigned, v, r, s);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
