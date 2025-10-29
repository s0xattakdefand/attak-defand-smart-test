// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECMA - Elliptic Curve Modular Arithmetic
 * @dev Complete smart contract for high-performance modular arithmetic on secp256k1 field.
 *      Implements modular addition, subtraction, multiplication, inversion, and exponentiation.
 *      Fixed: Removed all `emit` from `pure` and `view` functions to eliminate state modification errors.
 *      Events are now only emitted in state-changing functions (none here, so events removed).
 *      All functions are `pure` or `view` as appropriate.
 * @author Grok
 */
contract ECMA {
    // secp256k1 field modulus P
    uint256 public constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Events removed: cannot emit in pure/view functions
    // If you need events, create a separate stateful contract

    /**
     * @dev Modular addition: (a + b) mod P
     * @param a First operand
     * @param b Second operand
     * @return result (a + b) mod P
     */
    function modAdd(uint256 a, uint256 b) public pure returns (uint256 result) {
        unchecked {
            result = (a + b) % P;
        }
        return result;
    }

    /**
     * @dev Modular subtraction: (a - b) mod P
     * @param a First operand
     * @param b Second operand
     * @return result (a - b) mod P
     */
    function modSub(uint256 a, uint256 b) public pure returns (uint256 result) {
        unchecked {
            result = (a >= b) ? (a - b) : (P - (b - a));
        }
        return result;
    }

    /**
     * @dev Modular multiplication: (a * b) mod P
     * @param a First operand
     * @param b Second operand
     * @return result (a * b) mod P
     */
    function modMul(uint256 a, uint256 b) public pure returns (uint256 result) {
        uint256 prod;
        assembly {
            prod := mulmod(a, b, P)
        }
        result = prod;
        return result;
    }

    /**
     * @dev Modular inverse using Fermat's Little Theorem: a^(P-2) mod P
     * @param a Number to invert (must be non-zero)
     * @return inv a^(-1) mod P
     */
    function modInv(uint256 a) public pure returns (uint256 inv) {
        require(a != 0 && a < P, "Invalid input: a must be in [1, P-1]");
        inv = modExp(a, P - 2);
        return inv;
    }

    /**
     * @dev Modular exponentiation: base^exponent mod P
     *      Uses binary exponentiation with assembly for speed
     *      Fixed: No emit, no state changes → pure function
     * @param base Base number
     * @param exponent Exponent
     * @return result base^exponent mod P
     */
    function modExp(uint256 base, uint256 exponent) public pure returns (uint256 result) {
        result = 1;
        base = base % P;
        uint256 currentExp = exponent;

        assembly {
            let i := 0
            for { } lt(i, 256) { i := add(i, 1) } {
                let bit := and(currentExp, shl(sub(255, i), 1))
                if iszero(iszero(bit)) {
                    result := mulmod(result, base, P)
                }
                base := mulmod(base, base, P)
            }
        }

        return result;
    }

    /**
     * @dev Batch modular multiplication: (a[i] * b[i]) mod P
     * @param a Array of first operands
     * @param b Array of second operands
     * @return results Array of (a[i] * b[i]) mod P
     */
    function batchModMul(
        uint256[] memory a,
        uint256[] memory b
    ) public pure returns (uint256[] memory results) {
        require(a.length == b.length && a.length > 0 && a.length <= 100, "Invalid arrays");
        results = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            results[i] = modMul(a[i], b[i]);
        }
        return results;
    }

    /**
     * @dev Batch modular inverse: a[i]^(-1) mod P
     * @param a Array of numbers to invert
     * @return invs Array of inverses
     */
    function batchModInv(uint256[] memory a) public pure returns (uint256[] memory invs) {
        require(a.length > 0 && a.length <= 100, "Invalid array");
        invs = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            require(a[i] != 0 && a[i] < P, "Invalid input");
            invs[i] = modInv(a[i]);
        }
        return invs;
    }

    /**
     * @dev Safe modular addition with overflow check
     * @param a First operand
     * @param b Second operand
     * @return result (a + b) mod P
     */
    function safeModAdd(uint256 a, uint256 b) public pure returns (uint256 result) {
        uint256 sum = a + b;
        require(sum >= a, "Overflow in addition");
        result = sum % P;
        return result;
    }

    /**
     * @dev Reduce number modulo P
     * @param x Input number
     * @return reduced x mod P
     */
    function reduceModP(uint256 x) public pure returns (uint256 reduced) {
        return x % P;
    }

    /**
     * @dev Check if number is in field [0, P)
     * @param x Input number
     * @return isValid True if x < P
     */
    function isInField(uint256 x) public pure returns (bool isValid) {
        return x < P;
    }

    /**
     * @dev Compute (a * b + c) mod P in one step
     * @param a Multiplier
     * @param b Multiplicand
     * @param c Addend
     * @return result (a * b + c) mod P
     */
    function mulAddMod(uint256 a, uint256 b, uint256 c) public pure returns (uint256 result) {
        result = modAdd(modMul(a, b), c);
        return result;
    }
}