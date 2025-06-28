// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin v5 ─────────────────────────────────────────────── */
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/* ──────────────────────────────────────────────────────────────────
 *                        Device-to-Device Registry
 * ──────────────────────────────────────────────────────────────────
 *
 * • Owners register devices (address → metadata).
 * • One device proposes a D2D link, the target accepts, both can revoke.
 * • Events give off-chain agents a tamper-proof pairing ledger.
 */
contract Device2DRegistry is
    Ownable,
    Pausable,
    ReentrancyGuard
{
    /* ──────────  Device model  ────────── */
    struct Device {
        address owner;
        string  info;
        uint64  registered;
    }
    mapping(address => Device) private devices;
    event DeviceRegistered(address indexed dev, string info);

    /* ──────────  Link model  ─────────── */
    enum LinkStatus { NONE, PENDING, ACTIVE, REVOKED }
    struct Link {
        uint256   id;
        address   a;
        address   b;
        bytes32   reqHash;
        bytes32   accHash;
        uint64    created;
        uint64    expires;
        LinkStatus status;
        string    label;
    }
    uint256 private _nextId = 1;
    mapping(uint256 => Link) private _links;
    event LinkProposed(uint256 indexed id,address indexed a,address indexed b,uint64 expires,string label);
    event LinkActivated(uint256 indexed id,bytes32 reqHash,bytes32 accHash);
    event LinkRevoked(uint256 indexed id,string reason);

    /* ──────────  Constructor  ────────── */
    constructor() Ownable(msg.sender) { }   // ✔️ pass initialOwner

    /* ──────────  Device API  ────────── */
    function registerDevice(string calldata info) external whenNotPaused {
        require(devices[msg.sender].registered == 0, "already registered");
        devices[msg.sender] = Device(msg.sender, info, uint64(block.timestamp));
        emit DeviceRegistered(msg.sender, info);
    }
    function getDevice(address dev) external view returns (Device memory d) {
        d = devices[dev]; require(d.registered != 0,"unknown device");
    }

    /* ──────────  Link API  ─────────── */
    function proposeLink(
        address deviceB,
        bytes32 requestHash,
        uint32  ttlSecs,
        string  calldata label
    )
        external
        whenNotPaused
        nonReentrant
        returns (uint256 linkId)
    {
        require(deviceB != msg.sender, "self-link");
        require(devices[msg.sender].registered != 0, "register first");
        require(devices[deviceB].registered  != 0,   "target unreg");
        require(ttlSecs <= 30 days, "ttl > 30d");

        linkId = _nextId++;
        uint64 exp = ttlSecs == 0 ? 0 : uint64(block.timestamp)+ttlSecs;

        _links[linkId] = Link(
            linkId, msg.sender, deviceB,
            requestHash, 0,
            uint64(block.timestamp),
            exp,
            LinkStatus.PENDING,
            label
        );
        emit LinkProposed(linkId,msg.sender,deviceB,exp,label);
    }

    function acceptLink(uint256 id, bytes32 acceptHash)
        external
        whenNotPaused
        nonReentrant
    {
        Link storage L=_links[id];
        require(L.status==LinkStatus.PENDING,"not pending");
        require(L.b==msg.sender,"only target");
        if(L.expires!=0) require(block.timestamp<=L.expires,"expired");
        L.accHash=acceptHash;
        L.status =LinkStatus.ACTIVE;
        emit LinkActivated(id,L.reqHash,acceptHash);
    }

    function revokeLink(uint256 id,string calldata reason)
        external
        whenNotPaused
        nonReentrant
    {
        Link storage L=_links[id];
        require(L.status==LinkStatus.ACTIVE,"not active");
        require(msg.sender==L.a||msg.sender==L.b||msg.sender==owner(),
                "not authorised");
        L.status=LinkStatus.REVOKED;
        emit LinkRevoked(id,reason);
    }

    /* ──────────  Views  ─────────── */
    function getLink(uint256 id) external view returns (Link memory L){
        L=_links[id]; require(L.status!=LinkStatus.NONE,"no link");
    }
    function isLinked(address d1,address d2) external view returns(bool){
        for(uint256 id=1;id<_nextId;++id){
            Link storage L=_links[id];
            if(L.status==LinkStatus.ACTIVE &&
              ((L.a==d1&&L.b==d2)||(L.a==d2&&L.b==d1))) return true;
        }
        return false;
    }

    /* ──────────  Admin  ─────────── */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
