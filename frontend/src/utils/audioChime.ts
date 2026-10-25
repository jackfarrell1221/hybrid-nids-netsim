// utils/audioChime.ts — Native Web Audio API alert synthesizer for NEXUS SOC.
// Generates clear electronic alert chimes without external MP3/WAV dependencies.

class AudioAlertSynthesizer {
  private ctx: AudioContext | null = null;
  private lastPlayedTime = 0;
  private minIntervalMs = 1800; // Debounce so multiple alerts don't overwhelm

  private getContext(): AudioContext | null {
    if (typeof window === 'undefined') return null;
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
    return this.ctx;
  }

  /**
   * Plays a crisp, professional two-tone electronic chime.
   * Type 'critical': High-pitched urgency chime (880Hz -> 1320Hz)
   * Type 'warning': Moderate alert tone (587Hz -> 880Hz)
   */
  play(type: 'critical' | 'warning' = 'critical') {
    const now = Date.now();
    if (now - this.lastPlayedTime < this.minIntervalMs) {
      return;
    }
    this.lastPlayedTime = now;

    try {
      const ctx = this.getContext();
      if (!ctx) return;

      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gainNode = ctx.createGain();

      const audioNow = ctx.currentTime;

      if (type === 'critical') {
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(880, audioNow); // A5
        osc1.frequency.exponentialRampToValueAtTime(1320, audioNow + 0.12); // E6

        osc2.type = 'triangle';
        osc2.frequency.setValueAtTime(440, audioNow); // A4
        osc2.frequency.exponentialRampToValueAtTime(660, audioNow + 0.12);

        gainNode.gain.setValueAtTime(0.18, audioNow);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, audioNow + 0.38);

        osc1.connect(gainNode);
        osc2.connect(gainNode);
        gainNode.connect(ctx.destination);

        osc1.start(audioNow);
        osc2.start(audioNow);
        osc1.stop(audioNow + 0.4);
        osc2.stop(audioNow + 0.4);
      } else {
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(587.33, audioNow); // D5
        osc1.frequency.exponentialRampToValueAtTime(880, audioNow + 0.1);

        gainNode.gain.setValueAtTime(0.12, audioNow);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, audioNow + 0.28);

        osc1.connect(gainNode);
        gainNode.connect(ctx.destination);

        osc1.start(audioNow);
        osc1.stop(audioNow + 0.3);
      }
    } catch {
      // Audio playback suspended or browser autoplay policy blocked
    }
  }
}

export const audioAlert = new AudioAlertSynthesizer();
