// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CaptchaVerifier {
    address public captchaSigner;
    mapping(address => bool) public verifiedUsers;

    event CaptchaVerified(address indexed user);

    constructor(address _captchaSigner) {
        captchaSigner = _captchaSigner;
    }

    function verifyCaptcha(bytes calldata signature) external {
        require(!verifiedUsers[msg.sender], "Already verified");

        bytes32 message = keccak256(abi.encodePacked(msg.sender));
        bytes32 ethSignedMessage = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", message
        ));

        require(recoverSigner(ethSignedMessage, signature) == captchaSigner, "Invalid signature");

        verifiedUsers[msg.sender] = true;
        emit CaptchaVerified(msg.sender);
    }

    function isHuman(address user) external view returns (bool) {
        return verifiedUsers[user];
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
