// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AppIdentificationRegistry {
    struct App {
        address signer;
        string label;
        bool active;
    }

    mapping(bytes32 => App) public appRegistry;
    mapping(bytes32 => uint256) public appNonces;

    event AppRegistered(bytes32 indexed appId, address signer, string label);
    event AppVerified(bytes32 indexed appId, address caller, uint256 nonce);
    event SpoofAttempt(address indexed actor, string reason);

    function registerApp(bytes32 appId, address signer, string calldata label) external {
        require(appRegistry[appId].signer == address(0), "App already registered");
        appRegistry[appId] = App(signer, label, true);
        emit AppRegistered(appId, signer, label);
    }

    function verifyApp(
        bytes32 appId,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool) {
        App memory app = appRegistry[appId];
        require(app.active, "Inactive or unregistered App");

        bytes32 message = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(appId, nonce))));
        address recovered = _recoverSigner(message, signature);

        if (recovered != app.signer) {
            emit SpoofAttempt(msg.sender, "Invalid App signature");
            return false;
        }

        require(nonce > appNonces[appId], "Replay detected");
        appNonces[appId] = nonce;

        emit AppVerified(appId, msg.sender, nonce);
        return true;
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
