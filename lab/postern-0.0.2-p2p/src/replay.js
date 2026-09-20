'use strict'
// Anti-replay: a sliding bitmap window over per-session, per-direction message
// counters. UDP reorders and drops, so we cannot rely on strict sequencing;
// we accept any not-yet-seen counter within WINDOW of the highest seen.

const WINDOW = 2048 // messages of reordering tolerated

class ReplayWindow {
  constructor (window = WINDOW) {
    this.window = window
    this.max = -1
    this.bits = new Set() // counters seen within [max-window+1, max]
  }

  // Returns true if `counter` is fresh (and records it), false if replayed/old.
  check (counter) {
    if (!Number.isInteger(counter) || counter < 0) return false

    if (counter > this.max) {
      // advance; forget anything that falls out of the window
      const floor = counter - this.window
      for (const c of this.bits) if (c <= floor) this.bits.delete(c)
      this.bits.add(counter)
      this.max = counter
      return true
    }

    if (counter <= this.max - this.window) return false // too old
    if (this.bits.has(counter)) return false            // replay
    this.bits.add(counter)
    return true
  }
}

module.exports = { ReplayWindow, WINDOW }
