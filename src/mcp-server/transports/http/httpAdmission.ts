/**
 * @fileoverview Bounded non-queuing HTTP admission with reserved per-principal capacity.
 * @module mcp-server/transports/http/httpAdmission
 */
import { HttpLimitError, type HttpSecurity } from './httpSecurity.js';

/** An idempotent release function. Hold leases until work or stream actually ends. */
export type AdmissionRelease = () => void;
type Kind = 'requests' | 'sessions' | 'streams' | 'initializations';
interface PrincipalCounters {
  requests: number;
  sessions: number;
  streams: number;
  initializations: number;
  rate: number;
  window: number;
}

/** No waiting queue: saturation rejects immediately; one principal cannot fill global capacity. */
export class HttpAdmission {
  private readonly principals = new Map<string, PrincipalCounters>();
  private readonly totals = {
    requests: 0,
    sessions: 0,
    streams: 0,
    initializations: 0,
  };
  constructor(private readonly policy: HttpSecurity) {}

  /** Reserve resource capacity before allocation; counters have a hard cardinality cap. */
  acquire(kind: Kind, principal: string): AdmissionRelease {
    const now = Date.now();
    for (const [key, counters] of this.principals) {
      if (
        now - counters.window >= 60000 &&
        !counters.requests &&
        !counters.sessions &&
        !counters.streams &&
        !counters.initializations
      )
        this.principals.delete(key);
    }
    let counters = this.principals.get(principal);
    if (!counters) {
      if (this.principals.size >= this.policy.maxPrincipals)
        throw new HttpLimitError(503, 'Admission accounting capacity reached.');
      counters = {
        requests: 0,
        sessions: 0,
        streams: 0,
        initializations: 0,
        rate: 0,
        window: now,
      };
      this.principals.set(principal, counters);
    }
    if (now - counters.window >= 60000) {
      counters.window = now;
      counters.rate = 0;
    }
    const global = {
      requests: this.policy.maxRequests,
      sessions: this.policy.maxSessions,
      streams: this.policy.maxStreams,
      initializations: this.policy.maxInitializations,
    };
    const local = {
      requests: this.policy.maxRequestsPerPrincipal,
      sessions: this.policy.maxSessionsPerPrincipal,
      streams: this.policy.maxStreamsPerPrincipal,
      initializations: 1,
    };
    if (this.totals[kind] >= global[kind] || counters[kind] >= local[kind])
      throw new HttpLimitError(429, 'Concurrent resource limit reached.');
    if (kind === 'requests' && counters.rate >= this.policy.requestsPerMinute)
      throw new HttpLimitError(429, 'Request rate limit reached.');
    if (kind === 'requests') counters.rate++;
    this.totals[kind]++;
    counters[kind]++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.totals[kind]--;
      counters[kind]--;
    };
  }

  /** Aggregate counts for assertions and operational health; contains no identity data. */
  snapshot(): Readonly<typeof this.totals> & { principals: number } {
    return { ...this.totals, principals: this.principals.size };
  }
}
