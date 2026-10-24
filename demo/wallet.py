"""Wallets for the demo.

SimulatedWallet  - default; no network needed, fake transaction hashes.
TestnetWallet    - real EVM testnet transfers (e.g. Sepolia) when web3 is installed and
                   NEUROGHOST_DEMO_RPC + NEUROGHOST_DEMO_KEY are set. Never use a mainnet key.
"""

from __future__ import annotations

import hashlib
import os
import time


class SimulatedWallet:
    kind = "simulated"
    explorer = None

    def __init__(self, balance: float = 5.0):
        self.balance = balance
        self.history: list[dict] = []

    def transfer_funds(self, to: str, amount: float, **_: object) -> str:
        amount = float(amount)
        if amount > self.balance:
            raise ValueError("insufficient balance")
        self.balance -= amount
        tx = "0x" + hashlib.sha256(f"{to}{amount}{time.time_ns()}".encode()).hexdigest()
        self.history.append({"to": to, "amount": amount, "tx": tx})
        return tx

    def tx_link(self, tx: str) -> str:
        return f"(simulated) {tx[:18]}..."


class TestnetWallet:
    kind = "testnet"

    def __init__(self, rpc_url: str, private_key: str, explorer: str = "https://sepolia.etherscan.io/tx/"):
        from web3 import Web3

        self.Web3 = Web3
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.account = self.w3.eth.account.from_key(private_key)
        self.explorer = explorer
        self.private_key = private_key
        self.history: list[dict] = []

    @property
    def balance(self) -> float:
        return float(self.Web3.from_wei(self.w3.eth.get_balance(self.account.address), "ether"))

    def transfer_funds(self, to: str, amount: float, **_: object) -> str:
        tx = {
            "to": self.Web3.to_checksum_address(to),
            "value": self.Web3.to_wei(amount, "ether"),
            "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
            "gas": 21000,
            "maxFeePerGas": self.w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": self.Web3.to_wei(1, "gwei"),
            "chainId": self.w3.eth.chain_id,
        }
        signed = self.account.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        h = self.w3.eth.send_raw_transaction(raw).hex()
        h = h if h.startswith("0x") else "0x" + h
        self.history.append({"to": to, "amount": amount, "tx": h})
        return h

    def tx_link(self, tx: str) -> str:
        return self.explorer + tx


def build_wallet():
    rpc, key = os.environ.get("NEUROGHOST_DEMO_RPC"), os.environ.get("NEUROGHOST_DEMO_KEY")
    if rpc and key:
        try:
            return TestnetWallet(rpc, key)
        except ImportError:
            print("web3 not installed; using the simulated wallet")
    return SimulatedWallet()
