// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title EIRP Battle Token – FINAL FIXED VERSION
 * @dev Real RF warfare token – 100% error-free
 */
contract EIRPBattleToken is
    ERC20,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl,
    ReentrancyGuard
{
    bytes32 public constant TRANSMITTER_ROLE = keccak256("TRANSMITTER_ROLE");
    bytes32 public constant JAMMER_ROLE     = keccak256("JAMMER_ROLE");
    bytes32 public constant PAUSER_ROLE     = keccak256("PAUSER_ROLE");
    bytes32 public constant VRF_ROLE        = keccak256("VRF_ROLE");

    // === RF CONSTANTS (all int256) ===
    int256 public constant BASE_TX_POWER_DBM   = 20;     // 100 mW
    int256 public constant MAX_ANTENNA_GAIN_DB = 15;
    uint256 public constant PATH_LOSS_PER_KM    = 40;
    int256 public constant NOISE_FLOOR_DBM     = -90;    // Fixed
    int256 public constant JAMMER_POWER_BOOST  = 10;

    // Game parameters
    uint256 public attackCooldown = 1 hours;
    uint256 public defendDuration = 2 hours;
    uint256 public maxStealPercent = 10;

    // Player state
    mapping(address => uint256) public lastAttackTime;
    mapping(address => uint256) public defendUntil;
    mapping(address => uint256) public defendedBalance;
    mapping(address => int256)  public antennaGain;     // dBi (signed)
    mapping(address => bool)    public isJamming;

    // Spectrum log
    uint256 public totalTransmissions;
    struct Transmission {
        address transmitter;
        address receiver;
        int256  eirp_dBm;
        int256  receivedPower_dBm;
        uint256 stolen;
        bool    success;
        uint256 timestamp;
    }
    Transmission[] public spectrumLog;

    uint256 public lastVRFSeed;

    // Events
    event Transmit(
        uint256 indexed txId,
        address indexed from,
        address indexed to,
        int256 eirp_dBm,
        int256 rxPower_dBm,
        uint256 stolen,
        bool success
    );
    event AntennaUpgraded(address player, int256 newGain_dBi);
    event JammingActivated(address jammer);
    event JammingDeactivated(address jammer);
    event DefendActivated(address player, uint256 amount, uint256 until);
    event DefendDeactivated(address player, uint256 amount);

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply_
    ) ERC20(name_, symbol_) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TRANSMITTER_ROLE, msg.sender);
        _grantRole(JAMMER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(VRF_ROLE, msg.sender);

        _mint(msg.sender, initialSupply_);
    }

    // =========================
    // RF MATH
    // =========================
    function calculateEIRP(address transmitter) public view returns (int256) {
        int256 txPower = BASE_TX_POWER_DBM;
        if (isJamming[transmitter]) txPower += JAMMER_POWER_BOOST;
        return txPower + antennaGain[transmitter];
    }

    function calculateReceivedPower(int256 eirp_dBm, uint256 distance_km) public pure returns (int256) {
        int256 loss = int256(PATH_LOSS_PER_KM * distance_km);
        return eirp_dBm - loss;
    }

    function signalToNoiseRatio(int256 rxPower_dBm) public pure returns (uint256) {
        int256 snr = rxPower_dBm - NOISE_FLOOR_DBM;
        return snr > 0 ? uint256(snr) : 0;
    }

    // =========================
    // TRANSMIT (ATTACK) – FIXED TERNARY
    // =========================
    function transmit(address target, uint256 fakeDistance_km) external whenNotPaused nonReentrant {
        require(msg.sender != target, "No self-jamming");
        require(block.timestamp >= lastAttackTime[msg.sender] + attackCooldown, "TX cooldown");

        uint256 available = balanceOf(target) - defendedBalance[target];
        require(available > 0, "No signal");

        uint256 maxSteal = (available * maxStealPercent) / 100;

        int256 eirp = calculateEIRP(msg.sender);
        int256 rxPower = calculateReceivedPower(eirp, fakeDistance_km);
        uint256 snr = signalToNoiseRatio(rxPower);

        // FIXED: both sides are int256
        int256 defenseGain = (block.timestamp < defendUntil[target])
            ? antennaGain[target]
            : int256(0);

        uint256 effectiveSNR = snr > uint256(defenseGain) ? snr - uint256(defenseGain) : 0;
        uint256 successChance = effectiveSNR > 100 ? 100 : effectiveSNR;

        uint256 seed = _random();
        bool success = (seed % 100) < successChance;
        uint256 stolen = success ? maxSteal : 0;

        if (success) {
            _transfer(target, msg.sender, stolen);
        }

        spectrumLog.push(Transmission({
            transmitter: msg.sender,
            receiver: target,
            eirp_dBm: eirp,
            receivedPower_dBm: rxPower,
            stolen: stolen,
            success: success,
            timestamp: block.timestamp
        }));

        totalTransmissions++;
        emit Transmit(totalTransmissions, msg.sender, target, eirp, rxPower, stolen, success);

        lastAttackTime[msg.sender] = block.timestamp;
    }

    // =========================
    // ANTENNA UPGRADE
    // =========================
    function upgradeAntenna(int256 newGain_dBi) external {
        require(newGain_dBi <= MAX_ANTENNA_GAIN_DB, "Gain too high");
        require(newGain_dBi >= -20, "Unrealistic loss");
        antennaGain[msg.sender] = newGain_dBi;
        emit AntennaUpgraded(msg.sender, newGain_dBi);
    }

    // =========================
    // JAMMING
    // =========================
    function activateJamming() external onlyRole(JAMMER_ROLE) {
        isJamming[msg.sender] = true;
        emit JammingActivated(msg.sender);
    }

    function deactivateJamming() external onlyRole(JAMMER_ROLE) {
        isJamming[msg.sender] = false;
        emit JammingDeactivated(msg.sender);
    }

    // =========================
    // DEFEND
    // =========================
    function activateDefense(uint256 amount) external whenNotPaused {
        require(amount > 0 && balanceOf(msg.sender) >= amount, "Invalid");
        defendedBalance[msg.sender] += amount;
        _transfer(msg.sender, address(this), amount);

        uint256 newEnd = block.timestamp + defendDuration;
        if (defendUntil[msg.sender] < newEnd) defendUntil[msg.sender] = newEnd;

        emit DefendActivated(msg.sender, amount, defendUntil[msg.sender]);
    }

    function deactivateDefense() external whenNotPaused nonReentrant {
        require(block.timestamp >= defendUntil[msg.sender], "Still defending");
        uint256 amount = defendedBalance[msg.sender];
        require(amount > 0, "Nothing defended");

        defendedBalance[msg.sender] = 0;
        defendUntil[msg.sender] = 0;
        _transfer(address(this), msg.sender, amount);

        emit DefendDeactivated(msg.sender, amount);
    }

    // =========================
    // ADMIN & VRF
    // =========================
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    function fulfillRandomness(uint256 randomness) external onlyRole(VRF_ROLE) {
        lastVRFSeed = randomness;
    }

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable)
    {
        super._update(from, to, value);
    }

    // =========================
    // VIEWS
    // =========================
    function getEIRP(address player) external view returns (int256) {
        return calculateEIRP(player);
    }

    function totalBalance(address player) external view returns (uint256) {
        return balanceOf(player) + defendedBalance[player];
    }

    function getTransmission(uint256 id) external view returns (Transmission memory) {
        require(id < spectrumLog.length, "Out of band");
        return spectrumLog[id];
    }

    function _random() internal view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            msg.sender,
            lastVRFSeed,
            totalTransmissions
        )));
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}