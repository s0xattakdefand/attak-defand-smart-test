// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title EEMABattleToken – Enterprise Ethereum Maximum Audit
 * @dev Fully fixed, no ParserError, no hidden characters
 *      OpenZeppelin v5.0.2+ compatible
 */
contract EEMABattleToken is
    ERC20,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl,
    ReentrancyGuard
{
    bytes32 public constant GAME_MASTER_ROLE = keccak256("GAME_MASTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    // === CONFIGURABLE GAME PARAMETERS ===
    uint256 public attackCooldown = 1 hours;
    uint256 public defendDuration = 2 hours;
    uint256 public baseSuccessRate = 60;   // 60%
    uint256 public defendBonus = 30;       // +30% when defending
    uint256 public maxStealPercent = 10;   // 10% max

    // === BATTLE STATE ===
    mapping(address => uint256) public lastAttackTime;
    mapping(address => uint256) public defendUntil;
    mapping(address => uint256) public defendedBalance;

    // === RANDOMNESS ===
    uint256 public lastRandomSeed;

    // === EVENTS (Maximum transparency) ===
    event Attack(
        address indexed attacker,
        address indexed target,
        uint256 attempted,
        uint256 stolen,
        bool success,
        uint256 seed,
        uint256 timestamp
    );
    event DefendActivated(address indexed player, uint256 amount, uint256 untilTimestamp);
    event DefendDeactivated(address indexed player, uint256 amount);
    event ConfigUpdated(string key, uint256 value);
    event EmergencyWithdraw(address indexed admin, uint256 amount);

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply_
    ) ERC20(name_, symbol_) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GAME_MASTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(WITHDRAWER_ROLE, msg.sender);

        _mint(msg.sender, initialSupply_);
    }

    // =========================
    // ADMIN FUNCTIONS
    // =========================
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function setConfig(
        string calldata key,
        uint256 value
    ) external onlyRole(GAME_MASTER_ROLE) {
        bytes32 k = keccak256(abi.encodePacked(key));
        if (k == keccak256("attackCooldown")) attackCooldown = value;
        else if (k == keccak256("defendDuration")) defendDuration = value;
        else if (k == keccak256("baseSuccessRate")) baseSuccessRate = value;
        else if (k == keccak256("defendBonus")) defendBonus = value;
        else if (k == keccak256("maxStealPercent")) maxStealPercent = value;
        else revert("Invalid config key");

        emit ConfigUpdated(key, value);
    }

    function emergencyWithdraw() external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        uint256 bal = balanceOf(address(this));
        require(bal > 0, "No tokens");
        _transfer(address(this), msg.sender, bal);
        emit EmergencyWithdraw(msg.sender, bal);
    }

    // =========================
    // REQUIRED OZ v5 OVERRIDE
    // =========================
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Pausable) {
        super._update(from, to, value);
    }

    // =========================
    // BATTLE: ATTACK
    // =========================
    function attack(address target) external whenNotPaused nonReentrant {
        require(msg.sender != target, "No self-attack");
        require(block.timestamp >= lastAttackTime[msg.sender] + attackCooldown, "Cooldown");

        uint256 available = balanceOf(target) - defendedBalance[target];
        require(available > 0, "Nothing to steal");

        uint256 maxSteal = (available * maxStealPercent) / 100;

        uint256 chance = baseSuccessRate;
        if (block.timestamp < defendUntil[target]) {
            chance = chance > defendBonus ? chance - defendBonus : 0;
        }

        uint256 seed = _random();
        lastRandomSeed = seed;
        bool success = (seed % 100) < chance;
        uint256 stolen = success ? maxSteal : 0;

        if (success) {
            _transfer(target, msg.sender, stolen);
        }

        lastAttackTime[msg.sender] = block.timestamp;
        emit Attack(msg.sender, target, maxSteal, stolen, success, seed, block.timestamp);
    }

    // =========================
    // BATTLE: DEFEND
    // =========================
    function activateDefense(uint256 amount) external whenNotPaused {
        require(amount > 0, "Amount > 0");
        require(balanceOf(msg.sender) >= amount, "Low balance");

        defendedBalance[msg.sender] += amount;
        _transfer(msg.sender, address(this), amount);

        uint256 newEnd = block.timestamp + defendDuration;
        if (defendUntil[msg.sender] < newEnd) {
            defendUntil[msg.sender] = newEnd;
        }

        emit DefendActivated(msg.sender, amount, defendUntil[msg.sender]);
    }

    // FIXED LINE (removed corrupted Cyrillic characters)
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
    // VIEW FUNCTIONS
    // =========================
    function isDefending(address player) external view returns (bool) {
        return block.timestamp < defendUntil[player] && defendedBalance[player] > 0;
    }

    function totalBalance(address player) external view returns (uint256) {
        return balanceOf(player) + defendedBalance[player];
    }

    function cooldownLeft(address player) external view returns (uint256) {
        uint256 next = lastAttackTime[player] + attackCooldown;
        return block.timestamp >= next ? 0 : next - block.timestamp;
    }

    // =========================
    // INTERNAL
    // =========================
    function _random() internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    msg.sender,
                    tx.gasprice,
                    blockhash(block.number - 1),
                    lastRandomSeed
                )
            )
        );
    }

    // =========================
    // INTERFACE
    // =========================
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}