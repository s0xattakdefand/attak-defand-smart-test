// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract eBASH {
    // Enum for hash benchmark types
    enum HashType { None, SHA1, SHA256, SHA512, SHA3_256, SHA3_512, Keccak }

    // Structure for hash benchmark attestation
    struct Benchmark {
        address attester; // Trusted benchmarker
        string algorithm; // e.g., "SHA3-256"
        HashType hType; // Hash type enum
        uint256 cyclesPerByte; // Performance metric (cycles/byte)
        string platform; // e.g., "x86-64"
        bytes32 nonce; // Nonce to prevent replay/eavesdropping
        bool isValid; // Status
        uint256 timestamp; // Creation time
    }

    // Mapping to store benchmarks by ID
    mapping(uint256 => Benchmark) public benchmarks;
    // Mapping for authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Counter
    uint256 public benchmarkCount;
    // Admin
    address public admin;

    // Events
    event BenchmarkAttested(uint256 indexed benchmarkId, address indexed attester, string algorithm, HashType hType, uint256 cyclesPerByte, string platform, bytes32 nonce);
    event BatchBenchmarkAttested(uint256[] benchmarkIds, address attester);
    event BenchmarkRevoked(uint256 indexed benchmarkId, address indexed attester);
    event AttesterAuthorized(address indexed attester, bool authorized);

    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier onlyAuthorizedAttester() {
        require(authorizedAttesters[msg.sender] || msg.sender == admin, "Not authorized");
        _;
    }

    // Constructor
    constructor() {
        admin = msg.sender;
        benchmarkCount = 0;
    }

    // Authorize attester
    function authorizeAttester(address _attester, bool _status) external onlyAdmin {
        authorizedAttesters[_attester] = _status;
        emit AttesterAuthorized(_attester, _status);
    }

    // Single benchmark attestation
    function attestBenchmark(
        string calldata _algorithm,
        uint8 _hType,
        uint256 _cyclesPerByte,
        string calldata _platform,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_algorithm).length > 0, "Invalid algorithm");
        require(_hType >= 1 && _hType <= 6, "Invalid hash type");
        require(_cyclesPerByte > 0, "Cycles per byte must be >0");
        require(bytes(_platform).length > 0, "Invalid platform");
        require(_nonce != bytes32(0), "Invalid nonce");

        benchmarkCount++;
        benchmarks[benchmarkCount] = Benchmark({
            attester: msg.sender,
            algorithm: _algorithm,
            hType: HashType(_hType),
            cyclesPerByte: _cyclesPerByte,
            platform: _platform,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit BenchmarkAttested(benchmarkCount, msg.sender, _algorithm, HashType(_hType), _cyclesPerByte, _platform, _nonce);
        return benchmarkCount;
    }

    // Batch attestation (fixes undeclared 'attestBenchmark' error)
    function batchAttestBenchmarks(
        string[] calldata _algorithms,
        uint8[] calldata _hTypes,
        uint256[] calldata _cyclesPerBytes,
        string[] calldata _platforms,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _algorithms.length == _hTypes.length &&
            _hTypes.length == _cyclesPerBytes.length &&
            _cyclesPerBytes.length == _platforms.length &&
            _platforms.length == _nonces.length,
            "Mismatched arrays"
        );
        require(_algorithms.length > 0 && _algorithms.length <= 50, "Batch size invalid");

        uint256[] memory ids = new uint256[](_algorithms.length);

        for (uint256 i = 0; i < _algorithms.length; i++) {
            ids[i] = attestBenchmark(_algorithms[i], _hTypes[i], _cyclesPerBytes[i], _platforms[i], _nonces[i]);
        }

        emit BatchBenchmarkAttested(ids, msg.sender);
        return ids;
    }

    // Revoke
    function revokeBenchmark(uint256 _benchmarkId) external {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid ID");
        Benchmark storage benchmark = benchmarks[_benchmarkId];
        require(benchmark.attester == msg.sender || msg.sender == admin, "Not authorized");
        require(benchmark.isValid, "Already revoked");

        benchmark.isValid = false;
        emit BenchmarkRevoked(_benchmarkId, msg.sender);
    }

    // Verify
    function verifyBenchmark(uint256 _benchmarkId) external view returns (string memory status, string memory algorithm, HashType hType) {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid ID");
        Benchmark memory benchmark = benchmarks[_benchmarkId];
        return (benchmark.isValid ? "Valid" : "Revoked", benchmark.algorithm, benchmark.hType);
    }

    // Get details
    function getBenchmark(uint256 _benchmarkId)
        external
        view
        returns (
            address attester,
            string memory algorithm,
            HashType hType,
            uint256 cyclesPerByte,
            string memory platform,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid ID");
        Benchmark memory benchmark = benchmarks[_benchmarkId];
        return (
            benchmark.attester,
            benchmark.algorithm,
            benchmark.hType,
            benchmark.cyclesPerByte,
            benchmark.platform,
            benchmark.nonce,
            benchmark.isValid,
            benchmark.timestamp
        );
    }
}