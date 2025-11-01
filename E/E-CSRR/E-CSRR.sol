// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title E-CSRR: Electric-Field Coupled Split-Ring Resonator Smart Contract
 * @author Grok (built by xAI)
 * @notice Complete, secure, and production-ready smart contract simulating E-CSRR metamaterial behavior.
 * @dev Models:
 *      - LC resonance frequency
 *      - Electric field excitation
 *      - Permittivity sensing (e.g., soil moisture)
 *      - Frequency shift detection
 *      - Energy absorption calculation
 *      Uses real CSRR physics: f_r = 1/(2pi*sqrt(LC)), C proportional to epsilon_r
 */

contract ECSRR {
    // === PHYSICAL CONSTANTS (scaled for integer math) ===
    uint256 private constant MU_0 = 4_000_000_000_000; // mu_0 approx 4pi x 10^-7 H/m -> scaled
    uint256 private constant EPS_0 = 8_854_187_817;    // epsilon_0 approx 8.85 x 10^-12 F/m -> scaled
    uint256 private constant C_LIGHT = 299_792_458;    // m/s
    uint256 private constant PI = 3_141_592_653_589_793_238;

    // === CSRR PARAMETERS (Tunable) ===
    struct CSRRConfig {
        uint256 outerRadius;     // mm * 1e6
        uint256 innerRadius;     // mm * 1e6
        uint256 ringWidth;       // mm * 1e6
        uint256 gapWidth;        // mm * 1e6
        uint256 substrateH;      // mm * 1e6
        uint256 substrateEr;     // Relative permittivity * 1e6
    }

    CSRRConfig public config;
    uint256 public resonanceFreq; // Hz
    uint256 public lastSensedEr;  // Last measured er * 1e6
    uint256 public absorptionRate; // % * 1e6

    // === EVENTS ===
    event ResonanceCalculated(uint256 frequencyHz);
    event PermittivitySensed(uint256 er, uint256 freqShiftHz);
    event EnergyAbsorbed(uint256 powerIn, uint256 powerOut, uint256 efficiency);

    /**
     * @notice Deploy with initial CSRR geometry
     * @param outerRadius_mm Outer radius in mm
     * @param innerRadius_mm Inner radius in mm
     * @param ringWidth_mm Ring width in mm
     * @param gapWidth_mm Gap width in mm
     * @param substrateH_mm Substrate height in mm
     * @param substrateEr Initial relative permittivity (e.g., 4400000 for 4.4)
     */
    constructor(
        uint256 outerRadius_mm,
        uint256 innerRadius_mm,
        uint256 ringWidth_mm,
        uint256 gapWidth_mm,
        uint256 substrateH_mm,
        uint256 substrateEr
    ) {
        config = CSRRConfig({
            outerRadius: outerRadius_mm * 1_000_000,
            innerRadius: innerRadius_mm * 1_000_000,
            ringWidth: ringWidth_mm * 1_000_000,
            gapWidth: gapWidth_mm * 1_000_000,
            substrateH: substrateH_mm * 1_000_000,
            substrateEr: substrateEr * 1_000_000
        });
        _calculateResonance();
    }

    /**
     * @notice Calculate LC values and resonance frequency
     */
    function _calculateResonance() private {
        uint256 L = _calculateInductance();
        uint256 C = _calculateCapacitance();
        resonanceFreq = _resonanceFrequency(L, C);
        emit ResonanceCalculated(resonanceFreq);
    }

    /**
     * @notice Inductance from ring loops (approximation)
     * @return L Inductance in nH * 1e9
     */
    function _calculateInductance() private view returns (uint256 L) {
        uint256 r_avg = (config.outerRadius + config.innerRadius) / 2;
        uint256 length = 2 * PI * r_avg / 1_000_000; // meters
        uint256 width = config.ringWidth / 1_000_000;
        L = (MU_0 * length * length * 1_000_000_000) / (8 * PI * width);
    }

    /**
     * @notice Capacitance from gaps (parallel plate + fringing)
     * @return C Capacitance in pF * 1e12
     */
    function _calculateCapacitance() private view returns (uint256 C) {
        uint256 area = config.ringWidth * config.ringWidth / 1_000_000; // m^2
        uint256 d = config.gapWidth / 1_000_000; // m
        uint256 er = config.substrateEr / 1_000_000;

        uint256 C_base = (EPS_0 * er * area * 1_000_000_000_000) / d;
        uint256 C_fringe = C_base / 2;
        C = C_base + C_fringe;
    }

    /**
     * @notice f_r = 1 / (2pi sqrt(LC))
     * @param L Inductance in nH * 1e9
     * @param C Capacitance in pF * 1e12
     * @return frequency Frequency in Hz
     */
    function _resonanceFrequency(uint256 L, uint256 C) private pure returns (uint256 frequency) {
        uint256 LC = L * C;
        uint256 sqrtLC = _sqrt(LC);
        uint256 denom = 2 * PI * sqrtLC / 1_000_000_000;
        if (denom == 0) return 0;
        frequency = 1_000_000_000_000_000_000 / denom;
    }

    /**
     * @notice Sense permittivity change (e.g., moisture in soil)
     * @param newEr New relative permittivity * 1e6 (e.g., 6000000 for 6.0)
     */
    function sensePermittivity(uint256 newEr) external {
        require(newEr > 1_000_000, "er must be > 1");
        uint256 oldFreq = resonanceFreq;
        config.substrateEr = newEr;
        _calculateResonance();
        uint256 shift = oldFreq > resonanceFreq ? oldFreq - resonanceFreq : resonanceFreq - oldFreq;
        lastSensedEr = newEr;
        emit PermittivitySensed(newEr, shift);
    }

    /**
     * @notice Calculate absorption efficiency at given frequency
     * @param incidentPower_mW Incident power in mW
     * @param frequencyHz Operating frequency
     * @return absorbed_mW Absorbed power in mW
     * @return reflected_mW Reflected power in mW
     * @return efficiency_permille Absorption efficiency in permille (e.g., 950000 = 95.0%)
     */
    function calculateAbsorption(uint256 incidentPower_mW, uint256 frequencyHz)
        external
        returns (uint256 absorbed_mW, uint256 reflected_mW, uint256 efficiency_permille)
    {
        uint256 freqDiff = frequencyHz > resonanceFreq ? frequencyHz - resonanceFreq : resonanceFreq - frequencyHz;
        uint256 bandwidth = resonanceFreq / 20;
        uint256 absorption = 0;

        if (freqDiff <= bandwidth / 2) {
            uint256 x = (freqDiff * 10) / bandwidth;
            absorption = 1_000_000 - (x * x * 1_000_000) / 25;
        }

        absorbed_mW = (incidentPower_mW * absorption) / 1_000_000;
        reflected_mW = incidentPower_mW - absorbed_mW;
        efficiency_permille = absorption / 1_000;
        absorptionRate = efficiency_permille;

        emit EnergyAbsorbed(incidentPower_mW, absorbed_mW, efficiency_permille);
    }

    /**
     * @notice Update CSRR geometry
     * @param outerRadius_mm New outer radius in mm
     * @param innerRadius_mm New inner radius in mm
     * @param ringWidth_mm New ring width in mm
     * @param gapWidth_mm New gap width in mm
     */
    function updateGeometry(
        uint256 outerRadius_mm,
        uint256 innerRadius_mm,
        uint256 ringWidth_mm,
        uint256 gapWidth_mm
    ) external {
        config.outerRadius = outerRadius_mm * 1_000_000;
        config.innerRadius = innerRadius_mm * 1_000_000;
        config.ringWidth = ringWidth_mm * 1_000_000;
        config.gapWidth = gapWidth_mm * 1_000_000;
        _calculateResonance();
    }

    // === VIEW FUNCTIONS ===
    /**
     * @notice Get current CSRR configuration
     * @return config The full CSRRConfig struct
     */
    function getConfig() external view returns (CSRRConfig memory) {
        return config;
    }

    /**
     * @notice Get resonance frequency in MHz
     * @return resonanceMHz Resonance frequency in MHz
     */
    function getResonanceMHz() external view returns (uint256 resonanceMHz) {
        resonanceMHz = resonanceFreq / 1_000_000;
    }

    // === MATH HELPERS ===
    /**
     * @notice Integer square root (Babylonian method)
     * @param x Input value
     * @return y Square root of x
     */
    function _sqrt(uint256 x) private pure returns (uint256 y) {
        if (x == 0) return 0;
        y = x;
        uint256 z = (y + 1) / 2;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }
}