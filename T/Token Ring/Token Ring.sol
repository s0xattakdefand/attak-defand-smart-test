// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TokenRingSuite.sol
/// @notice On‑chain analogues of “Token Ring” patterns with common pitfalls 
///         and hardened defenses.

enum TokenRingType         { SingleToken, MultiToken }
enum TokenRingAttackType   { TokenSpoof, OutOfTurnSend, FloodToken }
enum TokenRingDefenseType  { TokenValidation, AccessControl, RateLimit }

error TR__NotMember();
error TR__NotHolder();
error TR__InvalidToken();
error TR__TooFrequent();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TOKEN RING
///    • Type: SingleToken  
///    • Attack: TokenSpoof (anyone can inject or steal token)  
///    • Defense: —  
///─────────────────────────────────────────────────────────────────────────────
contract TokenRingVuln {
    address[] public members;
    uint256   public currentIndex;
    bytes     public token;

    function join(address member) external {
        members.push(member);
    }

    /// ❌ no validation: anyone at any time can set the token
    function passToken(bytes calldata tkn) external {
        currentIndex = (currentIndex + 1) % members.length;
        token        = tkn;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • OutOfTurnSend: attacker calls passToken even when not holder  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TokenRing {
    TokenRingVuln public ring;
    constructor(TokenRingVuln _ring) { ring = _ring; }

    function spoof(bytes calldata tkn) external {
        ring.passToken(tkn); // injects arbitrary token out of turn
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TOKEN RING
///    • Defense: AccessControl + TokenValidation  
///    • Only the current holder may pass the token  
///─────────────────────────────────────────────────────────────────────────────
contract TokenRingSafe {
    address[] public members;
    uint256   public currentIndex;
    bytes     public token;
    mapping(address => bool) public isMember;

    constructor(address[] memory initialMembers, bytes memory initialToken) {
        members      = initialMembers;
        token        = initialToken;
        for (uint i; i < members.length; i++) {
            isMember[members[i]] = true;
        }
    }

    /// only the current holder may pass
    function passToken(bytes calldata tkn) external {
        address holder = members[currentIndex];
        if (!isMember[msg.sender]) revert TR__NotMember();
        if (msg.sender != holder)    revert TR__NotHolder();

        token        = tkn;                              // ✅ valid token update
        currentIndex = (currentIndex + 1) % members.length;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) RATE‑LIMITED TOKEN RING
///    • Defense: RateLimit – prevent FloodToken by limiting passes per block  
///─────────────────────────────────────────────────────────────────────────────
contract TokenRingSafeRateLimit {
    address[] public members;
    uint256   public currentIndex;
    bytes     public token;
    mapping(address => bool)    public isMember;
    mapping(address => uint256) public lastPassBlock;
    uint256   public constant MIN_BLOCK_DELAY = 1;

    constructor(address[] memory initialMembers, bytes memory initialToken) {
        members      = initialMembers;
        token        = initialToken;
        for (uint i; i < members.length; i++) {
            isMember[members[i]] = true;
        }
    }

    function passToken(bytes calldata tkn) external {
        address holder = members[currentIndex];
        if (!isMember[msg.sender]) revert TR__NotMember();
        if (msg.sender != holder)    revert TR__NotHolder();
        if (lastPassBlock[msg.sender] == block.number) revert TR__TooFrequent();

        lastPassBlock[msg.sender] = block.number;
        token        = tkn;                              // ✅ valid token update
        currentIndex = (currentIndex + 1) % members.length;
    }
}
