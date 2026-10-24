"""Deploy contracts/NeuroGhostAuditLog.sol to a testnet.

Needs:  pip install web3 py-solc-x
        NEUROGHOST_RPC_URL   e.g. a Sepolia RPC URL
        NEUROGHOST_CHAIN_KEY a TESTNET-ONLY private key with a little test ETH

Then put the printed address into config/settings.json -> chain.contract_address
and set chain.enabled to true. (You can also deploy the same file from Remix.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "contracts" / "NeuroGhostAuditLog.sol"


def main() -> int:
    try:
        import solcx
        from web3 import Web3
    except ImportError:
        print("Install first: pip install web3 py-solc-x")
        return 1
    rpc, key = os.environ.get("NEUROGHOST_RPC_URL"), os.environ.get("NEUROGHOST_CHAIN_KEY")
    if not (rpc and key):
        print("Set NEUROGHOST_RPC_URL and NEUROGHOST_CHAIN_KEY (testnet key only).")
        return 1

    solcx.install_solc("0.8.24")
    compiled = solcx.compile_source(SRC.read_text(), output_values=["abi", "bin"], solc_version="0.8.24")
    _, iface = compiled.popitem()

    w3 = Web3(Web3.HTTPProvider(rpc))
    acct = w3.eth.account.from_key(key)
    contract = w3.eth.contract(abi=iface["abi"], bytecode=iface["bin"])
    tx = contract.constructor().build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
    })
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    tx_hash = w3.eth.send_raw_transaction(raw)
    print("Deploying... tx", tx_hash.hex())
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print("NeuroGhostAuditLog deployed at", receipt.contractAddress)
    return 0


if __name__ == "__main__":
    sys.exit(main())
