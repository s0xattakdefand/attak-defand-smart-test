// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Environmental Failure Protection"
 *
 * We model a system that tracks environmental conditions (e.g., server room):
 *  - temperature (°C)
 *  - humidity (%)
 *  - power stability (bool)
 *  - emergencyShutdown flag
 *  - safety thresholds
 *
 * INSECURE VERSION:
 *  - Anyone can change thresholds
 *  - Anyone can falsify readings
 *  - Anyone can disable emergency shutdown
 *
 * SECURE VERSION:
 *  - Admin-only configuration
 *  - Trusted sensor oracle
 *  - Safe bounds on thresholds
 */

/*//////////////////////////////////////////////////////////////
//                 INSECURE / VULNERABLE VERSION
//////////////////////////////////////////////////////////////*/

contract EnvironmentalProtectionInsecure {
    struct Zone {
        int256 temperature;       // current temperature in °C
        int256 humidity;          // current humidity in %
        bool powerStable;         // true = power OK
        bool emergencyShutdown;   // true = shutdown active

        int256 maxSafeTemp;       // max allowed temperature
        int256 maxSafeHumidity;   // max allowed humidity

        address owner;            // who registered the zone
    }

    // zoneId -> Zone
    mapping(bytes32 => Zone) public zones;

    event ZoneRegistered(bytes32 indexed zoneId, address indexed owner);
    event ReadingsUpdated(bytes32 indexed zoneId, int256 temp, int256 humidity, bool powerStable);
    event ThresholdsUpdated(bytes32 indexed zoneId, int256 maxTemp, int256 maxHumidity);
    event EmergencyForced(bytes32 indexed zoneId, bool shutdown);

    /**
     * ⚠️ VULN #1:
     * Anyone can register any zoneId and overwrite an existing one.
     */
    function registerZone(
        bytes32 zoneId,
        int256 maxSafeTemp,
        int256 maxSafeHumidity
    ) external {
        zones[zoneId] = Zone({
            temperature: 0,
            humidity: 0,
            powerStable: true,
            emergencyShutdown: false,
            maxSafeTemp: maxSafeTemp,
            maxSafeHumidity: maxSafeHumidity,
            owner: msg.sender
        });

        emit ZoneRegistered(zoneId, msg.sender);
    }

    /**
     * ⚠️ VULN #2:
     * Any caller can update environmental readings for any zone.
     */
    function updateReadings(
        bytes32 zoneId,
        int256 temperature,
        int256 humidity,
        bool powerStable
    ) external {
        Zone storage z = zones[zoneId];
        z.temperature = temperature;
        z.humidity = humidity;
        z.powerStable = powerStable;

        emit ReadingsUpdated(zoneId, temperature, humidity, powerStable);
    }

    /**
     * ⚠️ VULN #3:
     * Any caller can change the safety thresholds.
     */
    function setThresholds(
        bytes32 zoneId,
        int256 maxSafeTemp,
        int256 maxSafeHumidity
    ) external {
        Zone storage z = zones[zoneId];
        z.maxSafeTemp = maxSafeTemp;
        z.maxSafeHumidity = maxSafeHumidity;

        emit ThresholdsUpdated(zoneId, maxSafeTemp, maxSafeHumidity);
    }

    /**
     * ⚠️ VULN #4:
     * Any caller can force emergencyShutdown on/off.
     */
    function forceEmergencyShutdown(bytes32 zoneId, bool shutdown) external {
        zones[zoneId].emergencyShutdown = shutdown;
        emit EmergencyForced(zoneId, shutdown);
    }

    /**
     * ⚠️ VULN #5:
     * Simple/naive safety check – fully attacker-controllable inputs.
     */
    function isEnvironmentSafe(bytes32 zoneId) external view returns (bool) {
        Zone memory z = zones[zoneId];

        if (z.emergencyShutdown) {
            return false;
        }

        bool withinTemp = z.temperature <= z.maxSafeTemp;
        bool withinHumidity = z.humidity <= z.maxSafeHumidity;

        return withinTemp && withinHumidity && z.powerStable;
    }
}

/*//////////////////////////////////////////////////////////////
//                           OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                    SECURE / DEFENDED VERSION
//////////////////////////////////////////////////////////////*/

contract EnvironmentalProtectionSecure is Ownable {
    struct Zone {
        int256 temperature;
        int256 humidity;
        bool powerStable;
        bool emergencyShutdown;

        int256 maxSafeTemp;
        int256 maxSafeHumidity;

        address zoneOwner;
        bool registered;
    }

    // Trusted sensor oracle that is allowed to send readings.
    address public sensorOracle;

    mapping(bytes32 => Zone) public zones;

    // Reasonable global bounds for safety thresholds.
    int256 public constant MIN_ALLOWED_TEMP = -40;  // °C
    int256 public constant MAX_ALLOWED_TEMP = 100;  // °C
    int256 public constant MIN_ALLOWED_HUMIDITY = 0;   // %
    int256 public constant MAX_ALLOWED_HUMIDITY = 100; // %

    event SensorOracleSet(address indexed oldOracle, address indexed newOracle);
    event ZoneRegistered(bytes32 indexed zoneId, address indexed zoneOwner, int256 maxTemp, int256 maxHumidity);
    event ThresholdsConfigured(bytes32 indexed zoneId, int256 maxTemp, int256 maxHumidity);
    event ReadingsIngested(bytes32 indexed zoneId, int256 temp, int256 humidity, bool powerStable);
    event EmergencyStatusSet(bytes32 indexed zoneId, bool shutdown);

    modifier onlyOracle() {
        require(msg.sender == sensorOracle, "NOT_ORACLE");
        _;
    }

    /**
     * Set the trusted sensor oracle address.
     */
    function setSensorOracle(address oracle) external onlyOwner {
        require(oracle != address(0), "ZERO_ORACLE");
        emit SensorOracleSet(sensorOracle, oracle);
        sensorOracle = oracle;
    }

    /**
     * Admin registers a new zone with safe thresholds.
     */
    function registerZone(
        bytes32 zoneId,
        address zoneOwner,
        int256 maxSafeTemp,
        int256 maxSafeHumidity
    ) external onlyOwner {
        require(zoneOwner != address(0), "BAD_OWNER");
        require(maxSafeTemp >= MIN_ALLOWED_TEMP && maxSafeTemp <= MAX_ALLOWED_TEMP, "BAD_TEMP_RANGE");
        require(maxSafeHumidity >= MIN_ALLOWED_HUMIDITY && maxSafeHumidity <= MAX_ALLOWED_HUMIDITY, "BAD_HUM_RANGE");

        Zone storage z = zones[zoneId];
        z.temperature = 0;
        z.humidity = 0;
        z.powerStable = true;
        z.emergencyShutdown = false;
        z.maxSafeTemp = maxSafeTemp;
        z.maxSafeHumidity = maxSafeHumidity;
        z.zoneOwner = zoneOwner;
        z.registered = true;

        emit ZoneRegistered(zoneId, zoneOwner, maxSafeTemp, maxSafeHumidity);
    }

    /**
     * Admin can tune thresholds within global safe bounds.
     */
    function configureThresholds(
        bytes32 zoneId,
        int256 maxSafeTemp,
        int256 maxSafeHumidity
    ) external onlyOwner {
        Zone storage z = zones[zoneId];
        require(z.registered, "ZONE_NOT_REGISTERED");

        require(maxSafeTemp >= MIN_ALLOWED_TEMP && maxSafeTemp <= MAX_ALLOWED_TEMP, "BAD_TEMP_RANGE");
        require(maxSafeHumidity >= MIN_ALLOWED_HUMIDITY && maxSafeHumidity <= MAX_ALLOWED_HUMIDITY, "BAD_HUM_RANGE");

        z.maxSafeTemp = maxSafeTemp;
        z.maxSafeHumidity = maxSafeHumidity;

        emit ThresholdsConfigured(zoneId, maxSafeTemp, maxSafeHumidity);
    }

    /**
     * Sensor oracle ingests real readings.
     */
    function ingestReadings(
        bytes32 zoneId,
        int256 temperature,
        int256 humidity,
        bool powerStable
    ) external onlyOracle {
        Zone storage z = zones[zoneId];
        require(z.registered, "ZONE_NOT_REGISTERED");

        // Basic sanity on sensor ranges
        require(temperature >= MIN_ALLOWED_TEMP && temperature <= MAX_ALLOWED_TEMP, "TEMP_OUT_OF_RANGE");
        require(humidity >= MIN_ALLOWED_HUMIDITY && humidity <= MAX_ALLOWED_HUMIDITY, "HUM_OUT_OF_RANGE");

        z.temperature = temperature;
        z.humidity = humidity;
        z.powerStable = powerStable;

        emit ReadingsIngested(zoneId, temperature, humidity, powerStable);

        // Optional: auto-trigger emergency flag if out of bounds
        if (
            temperature > z.maxSafeTemp ||
            humidity > z.maxSafeHumidity ||
            !powerStable
        ) {
            z.emergencyShutdown = true;
            emit EmergencyStatusSet(zoneId, true);
        }
    }

    /**
     * Only admin can manually set emergency flag (e.g., after inspection).
     */
    function setEmergencyShutdown(bytes32 zoneId, bool shutdown) external onlyOwner {
        Zone storage z = zones[zoneId];
        require(z.registered, "ZONE_NOT_REGISTERED");

        z.emergencyShutdown = shutdown;
        emit EmergencyStatusSet(zoneId, shutdown);
    }

    /**
     * Secure environment safety check.
     */
    function isEnvironmentSafe(bytes32 zoneId) external view returns (bool) {
        Zone memory z = zones[zoneId];
        if (!z.registered) return false;
        if (z.emergencyShutdown) return false;

        bool withinTemp = z.temperature <= z.maxSafeTemp;
        bool withinHumidity = z.humidity <= z.maxSafeHumidity;

        if (!withinTemp || !withinHumidity) return false;
        if (!z.powerStable) return false;

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EnvironmentalProtectionAttacker {
    EnvironmentalProtectionInsecure public target;

    constructor(address _target) {
        target = EnvironmentalProtectionInsecure(_target);
    }

    /**
     * Attack step #1:
     * Raise thresholds so high that nothing ever triggers.
     */
    function raiseThresholds(bytes32 zoneId) public {
        target.setThresholds(zoneId, int256(1e9), int256(1e9));
    }

    /**
     * Attack step #2:
     * Fake "good" readings even if real environment is bad.
     */
    function falsifyReadings(bytes32 zoneId) public {
        target.updateReadings(zoneId, 20, 40, true); // pretend safe values
    }

    /**
     * Attack step #3:
     * Disable emergency shutdown.
     */
    function disableEmergency(bytes32 zoneId) public {
        target.forceEmergencyShutdown(zoneId, false);
    }

    /**
     * One-click full exploit.
     */
    function fullAttack(bytes32 zoneId) external {
        raiseThresholds(zoneId);
        falsifyReadings(zoneId);
        disableEmergency(zoneId);
    }
}
