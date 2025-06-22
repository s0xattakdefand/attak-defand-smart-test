// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SpoofSuite.sol
/// @notice On‑chain analogues of four “Spoof” patterns:
///   1) Delegatecall‑Based Caller Spoofing  
///   2) tx.origin Spoofing  
///   3) Signature Spoofing (missing Ethereum prefix)  
///   4) Timestamp Spoofing  

error Spoof__NotOwner();
error Spoof__AuthFailed();
error Spoof__BadSignature();
error Spoof__TooEarly();

////////////////////////////////////////////////////////////////////////
// 1) DELEGATECALL‑BASED CALLER SPOOFING
//
//   • Vulnerable: uses delegatecall to an untrusted module for auth  
//   • Attack: malicious module writes over the host’s owner slot  
//   • Defense: use CALL and pass explicit caller for auth
////////////////////////////////////////////////////////////////////////
contract DelegateAuthVuln {
    address public module;
    address public owner;
    function setModule(address m) external { module = m; owner = msg.sender; }
    function privileged() external {
        // ❌ delegatecall reuses this contract’s context
        (bool ok,) = module.delegatecall(abi.encodeWithSignature("authorize()"));
        require(ok, "not authorized");
        // privileged action...
    }
}
contract Attack_DelegateAuth {
    DelegateAuthVuln public target;
    constructor(DelegateAuthVuln _t) { target = _t; }
    // fallback invoked via delegatecall
    fallback() external {
        // overwrite slot 1 (owner) with caller
        assembly { sstore(1, caller()) }
    }
}
contract DelegateAuthSafe {
    address public module;
    address public owner;
    constructor(address m) { module = m; owner = msg.sender; }
    function privileged() external {
        // ✅ use CALL and pass msg.sender for auth
        (bool ok, bytes memory ret) =
            module.call(abi.encodeWithSignature("authorize(address)", msg.sender));
        require(ok && abi.decode(ret,(bool)), "not authorized");
        // privileged action...
    }
}

////////////////////////////////////////////////////////////////////////
// 2) tx.origin SPOOFING
//
//   • Vulnerable: authenticates via tx.origin  
//   • Attack: a malicious contract can proxy a call so tx.origin remains EOA  
//   • Defense: use msg.sender exclusively for auth
////////////////////////////////////////////////////////////////////////
contract OriginAuthVuln {
    address public owner;
    constructor() { owner = msg.sender; }
    function adminAction() external view returns (string memory) {
        require(tx.origin == owner, "!owner");
        return "done";
    }
}
contract Attack_OriginAuth {
    OriginAuthVuln public target;
    constructor(OriginAuthVuln _t) { target = _t; }
    function hijack() external view returns (string memory) {
        // tx.origin is still EOA, so this passes
        return target.adminAction();
    }
}
contract OriginAuthSafe {
    address public owner;
    constructor() { owner = msg.sender; }
    function adminAction() external view returns (string memory) {
        require(msg.sender == owner, "!owner");
        return "done";
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SIGNATURE SPOOFING (MISSING ETH PREFIX)
// 
//   • Vulnerable: uses ecrecover on raw message hash  
//   • Attack: replay signature for crafted pre‑hashed data  
//   • Defense: wrap with "\x19Ethereum Signed Message" prefix
////////////////////////////////////////////////////////////////////////
library SigLib {
    function recoverRaw(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "invalid");
    }
}
contract SignatureAuthVuln {
    mapping(address=>bool) public admins;
    constructor() { admins[msg.sender] = true; }
    function isAdmin(bytes32 msgHash, bytes memory sig) external view returns(bool) {
        // ❌ no Ethereum msg prefix
        address signer = SigLib.recoverRaw(msgHash, sig);
        return admins[signer];
    }
}
contract SignatureAuthSafe {
    mapping(address=>bool) public admins;
    constructor() { admins[msg.sender] = true; }
    function isAdmin(bytes32 msgHash, bytes memory sig) external view returns(bool) {
        // ✅ prefix per EIP‑191
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        address signer = SigLib.recoverRaw(ethHash, sig);
        return admins[signer];
    }
}

////////////////////////////////////////////////////////////////////////
// 4) TIMESTAMP SPOOFING
//
//   • Vulnerable: uses block.timestamp for lock → miner can tweak  
//   • Attack: miner advances timestamp just enough to bypass lock  
//   • Defense: use block.number or multiple blocks delay
////////////////////////////////////////////////////////////////////////
contract TimeLockVuln {
    uint256 public releaseTime;
    uint256 public funds;
    function createLock(uint256 delay) external payable {
        releaseTime = block.timestamp + delay;
        funds = msg.value;
    }
    function withdraw() external {
        require(block.timestamp >= releaseTime, "too early");
        payable(msg.sender).transfer(funds);
        funds = 0;
    }
}
contract TimeLockSafe {
    uint256 public releaseBlock;
    uint256 public funds;
    function createLock(uint256 blocksDelay) external payable {
        releaseBlock = block.number + blocksDelay;
        funds = msg.value;
    }
    function withdraw() external {
        require(block.number >= releaseBlock, "too early");
        payable(msg.sender).transfer(funds);
        funds = 0;
    }
}
