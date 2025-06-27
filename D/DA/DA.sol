// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title On-chain Digital-to-Analog Converter (DAC) model
 *
 * Aimed at hardware tokenisation & audit trails:
 *  • Immutable resolution (bits) and reference voltage (mV).
 *  • Pure math:        V_out = (D / (2^N − 1)) · V_ref
 *  • `convert()`      – returns analog output for any digital code.
 *  • `writeCode()`    – stores + emits a log; off-chain MCU can poll.
 *
 * Security:
 *  • Only the owner may call `writeCode()` (can be delegated).
 *  • Reentrant-safe (no external calls inside state-mutating funcs).
 */

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract DigitalToAnalogConverter is Ownable, ReentrancyGuard {
    /* ──────────────────────  Immutables  ────────────────────── */

    uint8  public immutable resolutionBits;   // e.g. 8, 10, 12
    uint32 public immutable vRefMillivolts;   // reference voltage in mV

    /* ──────────────────────  State  ─────────────────────────── */

    uint32 public lastCode;   // last digital code written
    uint32 public lastMV;     // last analog value in mV

    event CodeWritten(
        address indexed caller,
        uint32          code,
        uint32          analogMV
    );

    /* ──────────────────────  Constructor  ───────────────────── */

    /**
     * @param _bits   Resolution (8–16 bits recommended).
     * @param _vRefMV Reference voltage in millivolts.
     */
    constructor(uint8 _bits, uint32 _vRefMV) Ownable(msg.sender) {
        require(_bits >= 2 && _bits <= 16, "bits 2-16");
        require(_vRefMV > 0, "vRef > 0");
        resolutionBits = _bits;
        vRefMillivolts = _vRefMV;
    }

    /* ──────────────────────  Pure conversion  ───────────────── */

    /**
     * @notice Convert a digital code to analog millivolts.
     * @dev    Pure – does no storage reads.
     * @param  code Digital input (0 … 2^N − 1).
     * @return mv   Analog output in millivolts (integer).
     */
    function convert(uint32 code) public view returns (uint32 mv) {
        uint32 maxCode = uint32((1 << resolutionBits) - 1);
        require(code <= maxCode, "out of range");
        // mv = code / max * vRef
        // To avoid precision loss, multiply first, then divide.
        mv = uint32((uint256(code) * vRefMillivolts) / maxCode);
    }

    /* ──────────────────────  Logged “write”  ────────────────── */

    /**
     * @notice Persist a code + emit an event (owner-only).
     * @dev    Off-chain controller can subscribe to the event
     *         and drive a physical DAC chip when triggered.
     */
    function writeCode(uint32 code) external onlyOwner nonReentrant {
        uint32 mv = convert(code);
        lastCode = code;
        lastMV   = mv;
        emit CodeWritten(msg.sender, code, mv);
    }
}
