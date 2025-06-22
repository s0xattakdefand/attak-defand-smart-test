// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

interface IRouter {
    function getAmountOut(uint256 inAmt, address inToken, address outToken) external view returns (uint256);
    function swap(address inToken, address outToken, uint256 inAmt, uint256 minOut) external returns (uint256);
}

/* ========== PING SWAP TYPES ========== */

// 1️⃣ Preview-Only Ping Swap
contract PreviewSwap {
    IRouter public router;

    constructor(address _r) {
        router = IRouter(_r);
    }

    function preview(address inT, address outT, uint256 amt) external view returns (uint256) {
        return router.getAmountOut(amt, inT, outT);
    }
}

// 2️⃣ Flash-Based Ping Swap
contract FlashPing {
    address public vault;

    function onFlashSwap(address token, uint256 amt, address pair) external {
        uint256 midPrice = IERC20(token).balanceOf(pair);
        require(midPrice > 0, "Empty pool");
        // Just probing logic
    }
}

// 3️⃣ Swap If Profitable
contract ProfitSwap {
    IRouter public router;
    address public owner;

    constructor(address _r) {
        router = IRouter(_r);
        owner = msg.sender;
    }

    function swapIfGood(address inT, address outT, uint256 amtIn, uint256 minOut) external {
        uint256 preview = router.getAmountOut(amtIn, inT, outT);
        require(preview >= minOut, "Not profitable");
        router.swap(inT, outT, amtIn, minOut);
    }
}

// 4️⃣ Bounce Swap
contract Bounce {
    IRouter public router;

    function roundTrip(address tokenA, address tokenB, uint256 amt) external {
        uint256 out1 = router.swap(tokenA, tokenB, amt, 0);
        uint256 out2 = router.swap(tokenB, tokenA, out1, 0);
        require(out2 >= amt, "Lossy swap");
    }
}

// 5️⃣ Cross Route Probe
contract RouteProbe {
    event RoutePing(address indexed route, uint256 quote);

    function testRoutes(address[] calldata routes, address inT, address outT, uint256 amt) external {
        for (uint i = 0; i < routes.length; i++) {
            uint256 out = IRouter(routes[i]).getAmountOut(amt, inT, outT);
            emit RoutePing(routes[i], out);
        }
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ 1 Signature Swap Verifier
contract SwapQuoteVerifier {
    function validate(bytes32 hash, bytes calldata sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

// 🛡️ 2 Route Drift Checker
contract PathGuard {
    mapping(bytes32 => bool) public validPaths;

    function set(bytes32 pathHash, bool ok) external {
        validPaths[pathHash] = ok;
    }

    function isValid(address inT, address outT) public view returns (bool) {
        return validPaths[keccak256(abi.encodePacked(inT, outT))];
    }
}

// 🛡️ 3 Min Swap Amount Enforcer
contract MinSwapFirewall {
    uint256 public min = 100e18;

    function validate(uint256 amt) external view {
        require(amt >= min, "Too small");
    }
}

// 🛡️ 4 Flash Duration Guard
contract FlashTimeGuard {
    mapping(address => uint256) public entry;

    modifier lock() {
        require(entry[msg.sender] == 0, "Locked");
        entry[msg.sender] = block.number;
        _;
        entry[msg.sender] = 0;
    }

    function pingSwap() external lock {
        // protect logic
    }
}

// 🛡️ 5 Entropy Drift Checker
contract SelectorEntropy {
    bytes4 public baseline;

    constructor(bytes4 _sig) {
        baseline = _sig;
    }

    fallback() external {
        require(hamming(msg.sig, baseline) <= 8, "Drift attack");
    }

    function hamming(bytes4 a, bytes4 b) internal pure returns (uint8 d) {
        for (uint256 i = 0; i < 4; i++) d += pop(uint8(a[i] ^ b[i]));
    }

    function pop(uint8 x) internal pure returns (uint8 c) {
        for (; x > 0; x >>= 1) c += x & 1;
    }
}
