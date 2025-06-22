// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ------------------------------------- */
/*       🔧 TYPES OF ROUTERS IN WEB3     */
/* ------------------------------------- */

// 1️⃣ Call Router
contract CallRouter {
    mapping(bytes4 => address) public targets;

    function registerRoute(bytes4 selector, address target) external {
        targets[selector] = target;
    }

    fallback() external payable {
        address target = targets[msg.sig];
        require(target != address(0), "No target");
        (bool ok, ) = target.call(msg.data);
        require(ok, "Call failed");
    }
}

// 2️⃣ Delegatecall Router
contract DelegatecallRouter {
    mapping(bytes4 => address) public logicMap;

    function setLogic(bytes4 selector, address logic) external {
        logicMap[selector] = logic;
    }

    function execute(bytes calldata data) external {
        bytes4 sel = bytes4(data);
        address logic = logicMap[sel];
        require(logic != address(0), "Missing logic");
        (bool ok, ) = logic.delegatecall(data);
        require(ok, "Delegatecall failed");
    }
}

// 3️⃣ Token Swap Router (DEX)
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract TokenSwapRouter {
    address public tokenA;
    address public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = _tokenA;
        tokenB = _tokenB;
    }

    function swap(uint256 amountIn) external {
        IERC20(tokenA).transferFrom(msg.sender, address(this), amountIn);
        uint256 amountOut = getRate(amountIn);
        IERC20(tokenB).transfer(msg.sender, amountOut);
    }

    function getRate(uint256 amountIn) public pure returns (uint256) {
        return (amountIn * 98) / 100; // 2% fee
    }
}

// 4️⃣ Governance Router
contract GovernanceRouter {
    mapping(uint256 => address) public proposalRouter;

    function routeProposal(uint256 id, bytes calldata data) external {
        address to = proposalRouter[id];
        require(to != address(0), "No DAO route");
        (bool ok, ) = to.call(data);
        require(ok, "Proposal failed");
    }

    function setDAO(uint256 id, address dao) external {
        proposalRouter[id] = dao;
    }
}

// 5️⃣ zkRollup/Bridge Router
contract zkBridgeRouter {
    event BridgeInitiated(address indexed user, uint256 amount, string l2Dest);

    function relayToL2(uint256 amount, string memory l2Address) external payable {
        emit BridgeInitiated(msg.sender, amount, l2Address);
    }
}

/* ------------------------------------- */
/*         💥 ATTACK SIMULATIONS         */
/* ------------------------------------- */

// 1️⃣ Selector Drift Hijack
contract DriftHijack {
    fallback() external {
        // activated when selector mismatches routing intent
    }
}

// 2️⃣ Delegation Override
contract DelegationExploit {
    function pwn() external {
        // malicious delegatecall logic
    }
}

// 3️⃣ Call Injection via Payload
contract PayloadInjector {
    function inject(bytes calldata maliciousData, address router) external {
        (bool ok, ) = router.call(maliciousData);
        require(ok, "Injection failed");
    }
}

// 4️⃣ Re-Entrant Route Bounce
contract ReentrantRouter {
    address public bounceTarget;

    constructor(address _target) {
        bounceTarget = _target;
    }

    fallback() external {
        bounceTarget.call(abi.encodeWithSignature("fallback()"));
    }
}

// 5️⃣ Malicious Router Preload
contract MaliciousRouter {
    function backdoor() external {
        // installed into DEX swap or fallback call
    }
}

/* ------------------------------------- */
/*       🛡 DEFENSE IMPLEMENTATIONS      */
/* ------------------------------------- */

// 🛡️ 1 Selector Whitelist Check
contract SelectorWhitelist {
    mapping(bytes4 => bool) public allowed;

    function setAllowed(bytes4 sel, bool enable) external {
        allowed[sel] = enable;
    }

    fallback() external {
        require(allowed[msg.sig], "Selector blocked");
    }
}

// 🛡️ 2 Target Auth Registry
contract TargetAuthRegistry {
    mapping(address => bool) public approved;

    function approve(address target, bool yes) external {
        approved[target] = yes;
    }

    function callApproved(address to, bytes calldata data) external {
        require(approved[to], "Target not approved");
        (bool ok, ) = to.call(data);
        require(ok, "Call failed");
    }
}

// 🛡️ 3 No Re-Route Bounce
contract RouteReentryGuard {
    bool private entered;

    modifier noBounce() {
        require(!entered, "Router loop");
        entered = true;
        _;
        entered = false;
    }

    function secureForward(address to, bytes calldata data) external noBounce {
        (bool ok, ) = to.call(data);
        require(ok, "Execution failed");
    }
}

// 🛡️ 4 Payload Signature Verifier
contract PayloadSigVerifier {
    function verify(bytes calldata payload, bytes calldata sig, address signer) external pure returns (bool) {
        bytes32 hash = keccak256(payload);
        return recover(hash, sig) == signer;
    }

    function recover(bytes32 hash, bytes calldata sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

// 🛡️ 5 Router Slot Lock
contract LockedRouterSlot {
    address public logic;
    bool public locked;

    function setLogic(address newLogic) external {
        require(!locked, "Router slot locked");
        logic = newLogic;
    }

    function lockSlot() external {
        locked = true;
    }
}
