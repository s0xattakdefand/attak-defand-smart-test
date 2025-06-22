// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ============================== */
/*        RIP ATTACK MODULES      */
/* ============================== */

// 1️⃣ Route Injection Attack
contract FakeRouteInjector {
    IRIPRouterRegistry public registry;

    constructor(address _reg) {
        registry = IRIPRouterRegistry(_reg);
    }

    function inject(bytes4 selector, address to) external {
        registry.registerRoute(selector, to, 1); // Fake shortest route
    }
}

// 2️⃣ Route Drift Spoof
contract DriftSpoofAttack {
    IRIPRouterRegistry public registry;

    function spoof(bytes4 selector, address badTarget) external {
        registry.registerRoute(selector, badTarget, 2); // Drift to attacker
    }
}

// 3️⃣ Recursive RIP Loop
contract RecursiveLoopInjector {
    IRIPRouterRegistry public registry;
    address self;

    constructor(address _reg) {
        registry = IRIPRouterRegistry(_reg);
        self = address(this);
    }

    function causeLoop(bytes4 selector) external {
        registry.registerRoute(selector, self, 1);
    }

    fallback() external {
        this.causeLoop(msg.sig); // infinite recursion via fallback
    }
}

// 4️⃣ Hop Overload (Gas Grief)
contract HopOverloadAttack {
    IRIPRouterRegistry public registry;

    function injectHeavyHop(bytes4 selector, address target) external {
        registry.registerRoute(selector, target, 255); // max hops
    }
}

// 5️⃣ Selector Mismatch Injection
contract MismatchSelectorAttack {
    IRIPRouterRegistry public registry;

    function mismatch(bytes4 selector, address invalidTarget) external {
        registry.registerRoute(selector, invalidTarget, 1); // incorrect mapping
    }
}


/* ============================== */
/*       RIP DEFENSE MODULES      */
/* ============================== */

// Interface used by attack/defense
interface IRIPRouterRegistry {
    function registerRoute(bytes4 selector, address target, uint8 hops) external;
}

// 🛡️ 1. RouteSigVerifier.sol
contract RouteSigVerifier {
    mapping(bytes4 => address) public expectedTargets;

    function setExpected(bytes4 selector, address target) external {
        expectedTargets[selector] = target;
    }

    function isValidRoute(bytes4 selector, address actual) external view returns (bool) {
        return expectedTargets[selector] == actual;
    }
}

// 🛡️ 2. MaxHopGuard.sol
contract MaxHopGuard {
    uint8 public constant MAX_HOPS = 20;

    function isHopAllowed(uint8 hops) external pure returns (bool) {
        return hops <= MAX_HOPS;
    }
}

// 🛡️ 3. RIPLoopDetector.sol
contract RIPLoopDetector {
    mapping(bytes4 => bool) public visited;

    modifier preventLoop(bytes4 selector) {
        require(!visited[selector], "RIP: loop detected");
        visited[selector] = true;
        _;
        visited[selector] = false;
    }
}

// 🛡️ 4. RouteAuthRegistry.sol
contract RouteAuthRegistry {
    mapping(address => bool) public canWrite;

    function authorize(address writer) external {
        canWrite[writer] = true;
    }

    function checkWrite(address writer) external view returns (bool) {
        return canWrite[writer];
    }
}

// 🛡️ 5. RouteEntropyCheck.sol
contract RouteEntropyCheck {
    function getEntropy(bytes4 sel) public pure returns (uint8 e) {
        uint32 x = uint32(sel);
        while (x != 0) {
            e++;
            x &= (x - 1);
        }
    }

    function isEntropySafe(bytes4 sel, uint8 threshold) external pure returns (bool) {
        return getEntropy(sel) <= threshold;
    }
}
