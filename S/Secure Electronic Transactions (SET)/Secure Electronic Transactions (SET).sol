// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                          COMMON LIBS & ERRORS
//////////////////////////////////////////////////////////////*/
error TX_Replayed();
error TX_BadSig();
error Escrow_NotAuthorized();
error HTLC_TooEarly();
error HTLC_TooLate();
error Channel_BadNonce();
error Channel_Expired();

library SigLib {
    /// @dev Recovers address from EIP‑712 digest + signature
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(h, v, r, s);
    }
}

/*//////////////////////////////////////////////////////////////
             1. SIGNATURE‑BASED PAYMENT (EIP‑712)
//////////////////////////////////////////////////////////////*/
contract SigPayment {
    using SigLib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant PAY_TYPEHASH =
        keccak256("Payment(address to,uint256 amount,uint256 nonce)");

    mapping(uint256 => bool) public usedNonce;

    event Paid(address indexed from, address indexed to, uint256 amount);

    constructor() {
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SigPayment"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Pay `amount` to `to`, authorised by EOA signature over (to,amount,nonce)
    function pay(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) external payable {
        if (usedNonce[nonce]) revert TX_Replayed();
        // construct EIP‑712 digest
        bytes32 structHash = keccak256(abi.encode(PAY_TYPEHASH, to, amount, nonce));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));

        // recover & verify
        if (digest.recover(sig) != msg.sender) revert TX_BadSig();

        usedNonce[nonce] = true;
        // transfer ETH
        (bool ok,) = to.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Paid(msg.sender, to, amount);
    }

    receive() external payable {}
}

/// @dev Replay attack: re-submits the same signed payment
contract Attack_SigReplay {
    SigPayment public target;
    address      public to;
    uint256      public amount;
    uint256      public nonce;
    bytes        public sig;

    constructor(
        SigPayment _t,
        address _to,
        uint256 _amount,
        uint256 _nonce,
        bytes memory _sig
    ) {
        target = _t;
        to      = _to;
        amount  = _amount;
        nonce   = _nonce;
        sig     = _sig;
    }

    function replay() external payable {
        target.pay{value: amount}(to, amount, nonce, sig);
    }
}

/*//////////////////////////////////////////////////////////////
               2. MULTI‑SIG ESCROW PAYMENT
//////////////////////////////////////////////////////////////*/
contract EscrowPayment {
    address public immutable payer;
    address public immutable payee;
    address public immutable arbiter;
    uint256 public immutable amount;

    enum State { AWAITING_DELIVERY, COMPLETE, REFUNDED }
    State  public state;

    event Released(address to, uint256 amt);
    event Refunded(address to, uint256 amt);

    constructor(address _payee, address _arbiter) payable {
        payer    = msg.sender;
        payee    = _payee;
        arbiter  = _arbiter;
        amount   = msg.value;
        state    = State.AWAITING_DELIVERY;
    }

    /// @notice Payer or arbiter confirms delivery → payee gets funds
    function confirmDelivery() external {
        if (msg.sender != payer && msg.sender != arbiter) revert Escrow_NotAuthorized();
        require(state == State.AWAITING_DELIVERY, "Bad state");
        state = State.COMPLETE;
        payable(payee).transfer(amount);
        emit Released(payee, amount);
    }

    /// @notice Payee or arbiter refunds → payer gets funds
    function refund() external {
        if (msg.sender != payee && msg.sender != arbiter) revert Escrow_NotAuthorized();
        require(state == State.AWAITING_DELIVERY, "Bad state");
        state = State.REFUNDED;
        payable(payer).transfer(amount);
        emit Refunded(payer, amount);
    }
}

/// @dev Unauthorized attacker tries to release without role
contract Attack_EscrowUnauthorized {
    EscrowPayment public esc;
    constructor(EscrowPayment _e) { esc = _e; }
    function attack() external {
        esc.confirmDelivery(); // reverts with Escrow_NotAuthorized
    }
}

/*//////////////////////////////////////////////////////////////
                    3. ATOMIC SWAP (HTLC)
//////////////////////////////////////////////////////////////*/
contract HTLC {
    address public immutable sender;
    address public immutable receiver;
    bytes32 public immutable hashlock;
    uint256 public immutable timelock; // timestamp

    bool public withdrawn;
    bool public refunded;
    uint256 public immutable amount;

    event Withdraw(address to, bytes32 preimage);
    event Refund(address to);

    constructor(
        address _receiver,
        bytes32 _hashlock,
        uint256 _durationSeconds
    ) payable {
        sender   = msg.sender;
        receiver = _receiver;
        hashlock = _hashlock;
        timelock = block.timestamp + _durationSeconds;
        amount   = msg.value;
    }

    /// @notice Receiver redeems with the correct preimage before timeout
    function withdraw(bytes32 preimage) external {
        if (withdrawn || refunded) revert HTLC_TooLate();
        if (keccak256(abi.encodePacked(preimage)) != hashlock) revert HTLC_TooEarly();
        withdrawn = true;
        payable(receiver).transfer(amount);
        emit Withdraw(receiver, preimage);
    }

    /// @notice Sender refunds after timeout
    function refund() external {
        if (withdrawn || refunded) revert HTLC_TooLate();
        if (block.timestamp < timelock) revert HTLC_TooEarly();
        refunded = true;
        payable(sender).transfer(amount);
        emit Refund(sender);
    }
}

/// @dev Attempt to claim with wrong preimage or too late
contract Attack_HTLCWrong {
    HTLC public h;
    constructor(HTLC _h) { h = _h; }
    function wrongClaim(bytes32 p) external {
        h.withdraw(p); // reverts if p != secret or too late
    }
}

/*//////////////////////////////////////////////////////////////
            4. PAYMENT CHANNEL (MICROPAYMENTS)
//////////////////////////////////////////////////////////////*/
contract PaymentChannel {
    using SigLib for bytes32;

    address public immutable sender;
    address payable public immutable recipient;
    uint256 public expiration;
    bytes32 public immutable DOMAIN;
    uint256 public maxNonce;

    bytes32 private constant CLOSE_TYPEHASH =
        keccak256("Close(uint256 amount,uint256 nonce)");

    event ChannelClosed(uint256 amount);

    constructor(
        address payable _recipient,
        uint256 durationSeconds
    ) payable {
        sender    = msg.sender;
        recipient = _recipient;
        expiration = block.timestamp + durationSeconds;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("PaymentChannel"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Recipient closes channel with sender’s off‑chain signature
    function close(
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) external {
        require(msg.sender == recipient, "Only recipient");
        require(block.timestamp <= expiration, "Channel expired");
        if (nonce <= maxNonce) revert Channel_BadNonce();

        // verify signature
        bytes32 structHash = keccak256(abi.encode(CLOSE_TYPEHASH, amount, nonce));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != sender) revert TX_BadSig();

        maxNonce = nonce;
        // transfer payout & refund rest
        uint256 total = address(this).balance;
        require(amount <= total, "Insufficient");
        recipient.transfer(amount);
        payable(sender).transfer(total - amount);
        emit ChannelClosed(amount);
    }

    /// @notice Sender can extend dispute window
    function extend(uint256 newExpiration) external {
        require(msg.sender == sender, "Only sender");
        expiration = newExpiration;
    }
}

/// @dev Attacker tries to close with an old state (nonce too low)
contract Attack_ChannelOldState {
    PaymentChannel public ch;
    uint256 public oldAmt;
    uint256 public oldNonce;
    bytes   public oldSig;

    constructor(
        PaymentChannel _ch,
        uint256 _amt,
        uint256 _nonce,
        bytes memory _sig
    ) {
        ch       = _ch;
        oldAmt   = _amt;
        oldNonce = _nonce;
        oldSig   = _sig;
    }

    function steal() external {
        ch.close(oldAmt, oldNonce, oldSig); // reverts Channel_BadNonce
    }
}
