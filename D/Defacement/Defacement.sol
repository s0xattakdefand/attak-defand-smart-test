// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DefacementSuite.sol
/// @notice On‑chain analogues of “Defacement” patterns:
///   Types: Page, File, DNS, UI  
///   AttackTypes: UnauthorizedChange, ContentInjection, ScriptInjection, Replay  
///   DefenseTypes: AccessControl, ImmutableOnce, RateLimit, Sanitization  

enum DefacementType         { Page, File, DNS, UI }
enum DefacementAttackType   { UnauthorizedChange, ContentInjection, ScriptInjection, Replay }
enum DefacementDefenseType  { AccessControl, ImmutableOnce, RateLimit, Sanitization }

error DCF__NotOwner();
error DCF__AlreadyDefaced();
error DCF__TooMany();
error DCF__BadContent();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DEFACEMENT REGISTRY
///
///    • anyone may overwrite content arbitrarily  
///    • Attack: UnauthorizedChange  
///─────────────────────────────────────────────────────────────────────────────
contract DefacementVuln {
    mapping(uint256 => string) public content;
    event Defaced(
        uint256 indexed id,
        DefacementType        dtype,
        string                newContent,
        DefacementAttackType  attack
    );

    function deface(uint256 id, DefacementType dtype, string calldata newContent) external {
        // ❌ no access control or validation
        content[id] = newContent;
        emit Defaced(id, dtype, newContent, DefacementAttackType.UnauthorizedChange);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: mass defacement & script injection
///
///    • Attack: ContentInjection, ScriptInjection  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Defacement {
    DefacementVuln public target;
    constructor(DefacementVuln _t) { target = _t; }

    /// mass‑deface multiple pages
    function massDeface(uint256[] calldata ids, DefacementType dtype, string calldata payload) external {
        for (uint i = 0; i < ids.length; i++) {
            target.deface(ids[i], dtype, payload);
        }
    }

    /// inject script into a specific page
    function injectScript(uint256 id, DefacementType dtype, string calldata script) external {
        string memory payload = string(abi.encodePacked("<script>", script, "</script>"));
        target.deface(id, dtype, payload);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DEFACEMENT WITH ACCESS CONTROL
///
///    • Defense: only owner may change content  
///─────────────────────────────────────────────────────────────────────────────
contract DefacementSafeAccess {
    mapping(uint256 => string) public content;
    address public owner;
    event Defaced(
        uint256 indexed id,
        DefacementType         dtype,
        string                 newContent,
        DefacementDefenseType  defense
    );

    constructor() {
        owner = msg.sender;
    }

    function deface(uint256 id, DefacementType dtype, string calldata newContent) external {
        if (msg.sender != owner) revert DCF__NotOwner();
        content[id] = newContent;
        emit Defaced(id, dtype, newContent, DefacementDefenseType.AccessControl);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE DEFACEMENT WITH IMMUTABLE & RATE‑LIMIT
///
///    • Defense: ImmutableOnce – only first defacement allowed  
///               RateLimit – cap operations per block  
///─────────────────────────────────────────────────────────────────────────────
contract DefacementSafeRateImmutable {
    mapping(uint256 => string) public content;
    mapping(uint256 => bool)   private _defaced;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS_PER_BLOCK = 3;
    address public owner;

    event Defaced(
        uint256 indexed id,
        DefacementType         dtype,
        string                 newContent,
        DefacementDefenseType  defense
    );

    constructor() {
        owner = msg.sender;
    }

    function deface(uint256 id, DefacementType dtype, string calldata newContent) external {
        if (msg.sender != owner)             revert DCF__NotOwner();
        if (_defaced[id])                    revert DCF__AlreadyDefaced();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS_PER_BLOCK) revert DCF__TooMany();

        _defaced[id] = true;
        content[id] = newContent;
        emit Defaced(id, dtype, newContent, DefacementDefenseType.ImmutableOnce);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE DEFACEMENT WITH CONTENT SANITIZATION
///
///    • Defense: reject content containing “<script>” to prevent XSS  
///─────────────────────────────────────────────────────────────────────────────
contract DefacementSafeSanitize {
    mapping(uint256 => string) public content;
    address public owner;

    event Defaced(
        uint256 indexed id,
        DefacementType         dtype,
        string                 newContent,
        DefacementDefenseType  defense
    );

    error DCF__BadContent();

    constructor() {
        owner = msg.sender;
    }

    function deface(uint256 id, DefacementType dtype, string calldata newContent) external {
        if (msg.sender != owner) revert DCF__NotOwner();
        bytes memory b = bytes(newContent);
        bytes memory pattern = bytes("<script>");
        for (uint i = 0; i + pattern.length <= b.length; i++) {
            bool match;
            for (uint j = 0; j < pattern.length; j++) {
                if (b[i+j] != pattern[j]) { match = false; break; }
                match = true;
            }
            if (match) revert DCF__BadContent();
        }
        content[id] = newContent;
        emit Defaced(id, dtype, newContent, DefacementDefenseType.Sanitization);
    }
}
