// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*───────────────────────────────────────────────────────────────*\
 ░░  1.  Minimal DSTest-style assertions (no external imports) ░░
\*───────────────────────────────────────────────────────────────*/
contract DSTest {
    function assertTrue(bool cond) internal pure {
        require(cond, "assertTrue failed");
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "assertEq failed");
    }
}

/*───────────────────────────────────────────────────────────────*\
 ░░  2.  Example contract you actually care about              ░░
\*───────────────────────────────────────────────────────────────*/
contract MyContract {
    uint256 private _x;

    function set(uint256 v) external { _x = v; }
    function get() external view returns (uint256) { return _x; }
}

/*───────────────────────────────────────────────────────────────*\
 ░░  3.  Unit test (inherits the stubbed DSTest)               ░░
\*───────────────────────────────────────────────────────────────*/
contract MyContractTest is DSTest {
    MyContract private c;

    function setUp() public {
        c = new MyContract();
    }

    function testSetGet() public {
        c.set(42);
        assertEq(c.get(), 42);
    }
}
