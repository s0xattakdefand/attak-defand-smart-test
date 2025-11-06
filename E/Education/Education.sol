// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Education: Decentralized Credential & Learning Platform
 * @author Grok (built by xAI)
 * @notice Complete, secure, and production-ready education system on blockchain.
 * @dev FIXED: "Member 'recover' not found on bytes32"
 *      -> In OpenZeppelin v5.0+, `ECDSA.recover()` is REMOVED from `.recover()` on bytes32
 *      -> SOLUTION: Import `ECDSA.sol` and use `ECDSA.recover(ethHash, signature)`
 *      -> Also added `using ECDSA for bytes32;` for optional syntax
 *      -> All previous errors (supportsInterface, address math) already fixed
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Education is AccessControl, ERC721URIStorage {
    using ECDSA for bytes32; // Optional: enables .recover() on bytes32 (v5+)

    bytes32 public constant INSTITUTION_ROLE = keccak256("INSTITUTION_ROLE");
    bytes32 public constant STUDENT_ROLE = keccak256("STUDENT_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // === STUDENT PROFILE ===
    struct Student {
        string did;
        string name;
        string emailHash;
        uint256 enrolledAt;
        uint256[] courseIds;
        uint256[] credentialIds;
    }

    // === COURSE ===
    struct Course {
        uint256 id;
        string title;
        string ipfsHash;
        address institution;
        uint256 creditHours;
        uint256 maxStudents;
        uint256 enrolledCount;
        bool active;
    }

    // === CREDENTIAL (W3C VC) ===
    struct Credential {
        uint256 id;
        uint256 courseId;
        address student;
        uint256 issuedAt;
        uint256 expiresAt;
        string ipfsHash;
        bytes signature;
    }

    // === MAPPINGS ===
    mapping(address => Student) public students;
    mapping(uint256 => Course) public courses;
    mapping(uint256 => Credential) public credentials;
    mapping(uint256 => bool) public isEnrolled;

    uint256 public nextCourseId = 1;
    uint256 public nextCredentialId = 1;
    uint256 private _tokenId = 0;

    // === EVENTS ===
    event StudentRegistered(address indexed student, string did);
    event CourseCreated(uint256 indexed courseId, string title, address institution);
    event Enrolled(uint256 indexed courseId, address indexed student);
    event CredentialIssued(uint256 indexed credId, address indexed student, uint256 courseId);
    event DiplomaMinted(uint256 indexed tokenId, address indexed student, uint256 credId);

    constructor() ERC721("EduDiploma", "EDUD") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(INSTITUTION_ROLE, msg.sender);
    }

    /**
     * @notice Override supportsInterface to resolve conflict
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @notice Helper: generate enrollment key
     */
    function _enrollmentKey(address user, uint256 courseId) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(user, courseId)));
    }

    /**
     * @notice Register student with DID
     */
    function registerStudent(
        string memory did,
        string memory name,
        string memory email
    ) external {
        require(bytes(students[msg.sender].did).length == 0, "Already registered");
        require(bytes(did).length > 0, "Invalid DID");

        students[msg.sender] = Student({
            did: did,
            name: name,
            emailHash: string(abi.encodePacked(keccak256(bytes(email)))),
            enrolledAt: block.timestamp,
            courseIds: new uint256[](0),
            credentialIds: new uint256[](0)
        });

        _grantRole(STUDENT_ROLE, msg.sender);
        emit StudentRegistered(msg.sender, did);
    }

    /**
     * @notice Institution creates course
     */
    function createCourse(
        string memory title,
        string memory ipfsHash,
        uint256 creditHours,
        uint256 maxStudents
    ) external onlyRole(INSTITUTION_ROLE) {
        uint256 courseId = nextCourseId++;
        courses[courseId] = Course({
            id: courseId,
            title: title,
            ipfsHash: ipfsHash,
            institution: msg.sender,
            creditHours: creditHours,
            maxStudents: maxStudents,
            enrolledCount: 0,
            active: true
        });
        emit CourseCreated(courseId, title, msg.sender);
    }

    /**
     * @notice Student enrolls in course
     */
    function enroll(uint256 courseId) external onlyRole(STUDENT_ROLE) {
        Course storage course = courses[courseId];
        require(course.active, "Course inactive");
        require(course.enrolledCount < course.maxStudents, "Full");

        uint256 key = _enrollmentKey(msg.sender, courseId);
        require(!isEnrolled[key], "Already enrolled");

        course.enrolledCount++;
        students[msg.sender].courseIds.push(courseId);
        isEnrolled[key] = true;
        emit Enrolled(courseId, msg.sender);
    }

    /**
     * @notice Issue credential + mint NFT diploma
     */
    function issueCredential(
        address student,
        uint256 courseId,
        string memory ipfsHash,
        uint256 expiresAt,
        bytes memory signature
    ) external onlyRole(INSTITUTION_ROLE) {
        Course memory course = courses[courseId];
        require(course.institution == msg.sender, "Not course owner");

        uint256 key = _enrollmentKey(student, courseId);
        require(isEnrolled[key], "Not enrolled");

        // Verify signature
        bytes32 vcHash = keccak256(abi.encodePacked(ipfsHash, student, courseId, expiresAt));
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(vcHash);

        // FIXED: Use ECDSA.recover() directly
        address signer = ECDSA.recover(ethHash, signature);
        require(signer == msg.sender, "Invalid signature");

        uint256 credId = nextCredentialId++;
        credentials[credId] = Credential({
            id: credId,
            courseId: courseId,
            student: student,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            ipfsHash: ipfsHash,
            signature: signature
        });

        students[student].credentialIds.push(credId);
        emit CredentialIssued(credId, student, courseId);

        // Mint NFT Diploma
        uint256 tokenId = ++_tokenId;
        _safeMint(student, tokenId);
        _setTokenURI(tokenId, ipfsHash);
        emit DiplomaMinted(tokenId, student, credId);
    }

    /**
     * @notice Verify credential
     */
    function verifyCredential(uint256 credId) external view returns (bool valid) {
        Credential memory cred = credentials[credId];
        if (cred.expiresAt != 0 && block.timestamp > cred.expiresAt) return false;

        bytes32 vcHash = keccak256(abi.encodePacked(cred.ipfsHash, cred.student, cred.courseId, cred.expiresAt));
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(vcHash);

        // Use ECDSA.recover()
        address signer = ECDSA.recover(ethHash, cred.signature);
        return signer == courses[cred.courseId].institution;
    }

    /**
     * @notice Get student profile
     */
    function getStudent(address student) external view returns (Student memory) {
        return students[student];
    }

    /**
     * @notice Get course details
     */
    function getCourse(uint256 courseId) external view returns (Course memory) {
        return courses[courseId];
    }

    /**
     * @notice Add institution
     */
    function addInstitution(address institution) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(INSTITUTION_ROLE, institution);
    }
}