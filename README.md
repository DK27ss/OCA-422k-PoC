## OCA/USDC 422k Exploit

**Chain:** BSC

**Date:** 2026-02-14

**Block:** 81,020,478

**Profit:** ~$422,361 USDC

**Root Cause:** `SwapHelper.sellOCA()` + `OCAToken.recycle()`

---

## Contracts

| Role | Address |
|------|---------|
| OCA Token | [`0xE0dAFD4592205067299A6ae269f68aa804f95419`](https://bscscan.com/address/0xE0dAFD4592205067299A6ae269f68aa804f95419) |
| SwapHelper (vulnerable) | [`0xE0D5eC0F754c442F37fbdf18266053309D5F6f55`](https://bscscan.com/address/0xE0D5eC0F754c442F37fbdf18266053309D5F6f55) |
| Mining Pool | [`0x59Ac98033d74A73A23B0Ef728A54B3032eE6c1D2`](https://bscscan.com/address/0x59Ac98033d74A73A23B0Ef728A54B3032eE6c1D2) |
| Withdrawal Address | [`0x77dE595b5BFF05c20788eBf94601c9F0181ECda3`](https://bscscan.com/address/0x77dE595b5BFF05c20788eBf94601c9F0181ECda3) |
| Attacker Contract | [`0x1A325174111db473e1Ce4e079a2Bd558B0164B31`](https://bscscan.com/address/0x1A325174111db473e1Ce4e079a2Bd558B0164B31) |
| Profit Recipient | [`0x4bCD06648a9315A233229B634B89011009F7b195`](https://bscscan.com/address/0x4bCD06648a9315A233229B634B89011009F7b195) |

---

## Summary

The OCA token on BSC was exploited through a design flaw in the token's "recycling" mechanism, the `SwapHelper` contract exposes a `sellOCA()` function that sells OCA for USDC on PancakeSwap, then calls `OCA.recycle()` to withdraw OCA directly from the pair's reserves, this mechanism causes a **deflation** the pair loses both its USDC (via the swap) and its OCA (via the recycle), with no compensation in return.

The attacker used a ~8.7M USDC flash loan from Moolah to amplify the price manipulation, then executed 3 rounds of `sellOCA` followed by a final swap to extract ~$422k from the pair.

---

## OCA Architecture

The OCA token implements a 100% buy tax mechanism and deflation via a `SwapHelper`

```
User
    │
    ├── Buy (Pair → User) : 100% tax, buyer receives 0 OCA
    │   └── 15% burn + 2% LP dividend + 43% mining pool + 40% treasury
    │
    ├── Sell (User → Pair) : 3% tax
    │   └── 1.8% burn + 1.2% mining pool, 97% goes to pair
    │
    └── sellOCA via SwapHelper : deflation mechanism
        └── Sells OCA → USDC, then recycles OCA from the pair
```

## Root Cause

The `SwapHelper` (`0xE0D5...6f55`) exposes two main functions:

- **`buyOCA(uint256)`** (sel. `0x062b1701`): Takes USDC from caller, swaps USDC→OCA via Router, sends OCA to caller
- **`sellOCA(uint256)`** (sel. `0x9c1dad28`): Takes OCA from caller, swaps OCA→USDC via Router, sends USDC to caller, then calls `recycle()`

### `recycle()` in the OCA token

```solidity
function recycle(address to, uint256 amount) external {
    require(msg.sender == swapHelper, "Only SwapHelper");
    require(balanceOf(uniswapV2Pair) >= amount, "Insufficient pair balance");

    // Transfers OCA directly FROM the pair to 'to'
    super._transfer(uniswapV2Pair, to, amount);

    // Updates reserves to reflect the new balance
    IUniswapV2Pair(uniswapV2Pair).sync();
}
```

The vulnerability lies in the interaction between `SwapHelper.sellOCA()` and `OCA.recycle()`, here is the full flow of `sellOCA(amount)`

```
sellOCA(amount):
  1. OCA.transferFrom(caller → SwapHelper, amount)           // Takes OCA from caller
  2. OCA.approve(Router, amount)                              // Approves the Router
  3. Router.swap(OCA→USDC, path, to=caller)                   // Swaps OCA→USDC
  │   └── Pair receives +OCA, sends -USDC to caller
  │
  4. OCA.recycle(SwapHelper, amount)                           // Calls recycle
  │   └── _transfer(Pair → SwapHelper, amount)                // Pulls OCA out of the Pair!
  │   └── Pair.sync()                                         // Updates reserves
  │
  5. OCA.transfer(miningPool, 40% * amount)                   // 40% → mining pool
  6. OCA.transfer(0xdead, 60% * amount)                       // 60% → burn
```

**The problem**: at step 3, the pair receives OCA and sends USDC, then at step 4, `recycle()` pulls those same OCA back out of the pair.

| Step | Pair receives | Pair loses |
|------|--------------|------------|
| Swap (step 3) | +OCA | **-USDC** (→ attacker) |
| Recycle (step 4) | — | **-OCA** (→ SwapHelper → burn/pool) |
| **Net balance** | **nothing** | **-USDC AND -OCA** |

The pair is drained on **both sides** with each `sellOCA` call.

Without a flashloan, the drainage is limited by existing reserves, the attacker uses a ~8.7M USDC flash loan to:

1. **Imbalance**: By swapping 8.7M USDC → OCA, the pair ends up with ~9.1M USDC and only ~2.6 OCA
2. **Maximize**: Each `sellOCA` converts OCA at an extremely favorable rate (the pair is flooded with USDC)
3. **Repeat**: 3 rounds are enough to drain >98% of the pair's USDC

The `recycle()` function violates a fundamental AMM invariant: **pair reserves should only be modified through swaps, liquidity adds/removes, or fees**, here `recycle()` performs a direct `_transfer` from the pair followed by a `sync()`, completely bypassing the pair contract's logic. It is equivalent to an unauthorized `skim()`, but called by a trusted contract.

---

## Initial State (block 81,020,477)

```
USDC/OCA Pair:
  USDC reserve : 427,369.50 USDC
  OCA reserve  : 987,305.96 OCA

Moolah:
  Available USDC : 8,704,860.14 USDC
```

Attack TX : https://app.blocksec.com/phalcon/explorer/tx/bsc/0x514141dac28a8a53f90312e94c58476615c2c5ce844d8d37999bdf8a66413d5c

### 1 — Flash loan

The attacker borrows **8,704,860 USDC** from Moolah. The flash loan is free (no fees) and must be repaid within the same transaction.

<img width="1623" height="311" alt="image" src="https://github.com/user-attachments/assets/930fd3a1-e117-46fb-bf38-6fce59d72ce9" />

### 2 — Round 1: Flash swap + sellOCA

**Flashswap**: The attacker uses a PancakeSwap flash swap to exchange 8.7M USDC for OCA.

```
Before: Pair(427k USDC, 987k OCA)
Swap:   8.7M USDC → 940,991 OCA
After:  Pair(9.1M USDC, 2.6 OCA)    ← pair massively imbalanced
```

<img width="1843" height="311" alt="image" src="https://github.com/user-attachments/assets/dd457311-1112-4388-b652-7a788a920db5" />

The attacker keeps 1% of the OCA (~9,409 OCA) for the final swap and calls `sellOCA(931,581 OCA)`

1. SwapHelper takes 931k OCA from the attacker
2. SwapHelper does a transferFrom of 25% (~2,445k OCA in the trace) to itself
3. SwapHelper swaps OCA→USDC via the Router, USDC goes to the attacker
4. `recycle()` pulls ~2,445k OCA directly from the pair to SwapHelper
5. `sync()` updates reserves
6. 40% OCA → mining pool, 60% OCA → burn

```
After Round 1:
  Pair USDC: 433,545 USDC
  Pair OCA:  46,314 OCA
  Attacker:  8,698,684 USDC
```

### 3 — Round 2

Same mechanism. The attacker re-swaps all USDC into the pair and repeats `sellOCA`.

```
After Round 2:
  Pair USDC: 435,617 USDC
  Pair OCA:  2,203 OCA
  Attacker:  8,696,612 USDC
```

### 4 — Round 3

```
After Round 3:
  Pair USDC: 437,698 USDC
  Pair OCA:  105 OCA
  Attacker:  8,694,530 USDC
```

<img width="2213" height="347" alt="image" src="https://github.com/user-attachments/assets/ecbf5a57-d10f-404a-86e6-f56203556f3d" />

### 5 — Final swap

The attacker sells the ~9,409 accumulated OCA (the 1% kept from each round) via a normal PancakeSwap swap

```
Swap: 9,409 OCA → 432,690 USDC
```

<img width="2194" height="531" alt="image" src="https://github.com/user-attachments/assets/a31d6afd-4c5b-4825-919f-dc0ed9ef3e4e" />

This swap is extremely profitable because the pair has almost no OCA left but still ~437k USDC.

### 6 — Repay & profit

```
Attacker's total USDC  : 9,127,221.49 USDC
Flash loan to repay    : 8,704,860.14 USDC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Gross profit           : 422,361.34 USDC
```

<img width="1694" height="196" alt="image" src="https://github.com/user-attachments/assets/918a637e-5a37-40f3-98be-ed6446fe1fee" />

The attacker repays the flash loan, then transfers **2,343 USDC** to `0x4bCD06648a9315A233229B634B89011009F7b195` and keeps the rest.

---

## Impact

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Pair USDC | 427,369.50 | 5,008.15 | **-422,361.34 (-98.8%)** |
| Pair OCA | 987,305.96 | 9,233.00 | **-978,072.96 (-99.1%)** |

| Metric | Value |
|--------|-------|
| Net profit | **~$422,361 USDC** |
| Gas used | 715,867 |
| Number of rounds | 3 + 1 final swap |

### Recycled OCA distribution (per round)

Each `recycle()` call pulls **2,445,154 OCA** from the pair, distributed as:
- **978,061 OCA (40%)** → Mining Pool (`0x59Ac...1D2`)
- **1,467,092 OCA (60%)** → Burn Address (`0xdead`)

---

### Expected result

```
[PASS] exec()
  >>> PROFIT : 422361.349112223479237938 USDC

  Assertions:
    - profit > 0
    - profit > 400,000 USDC
    - pair drained > 90%
```
