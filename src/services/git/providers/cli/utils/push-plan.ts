/**
 * @fileoverview Resolve explicit push destinations before any remote mutation.
 * @module services/git/providers/cli/utils/push-plan
 */
import {
  assertPushPolicy,
  normalizePushRef,
  type PushPolicyInput,
} from './push-policy.js';

/** Effective local configuration read by the scoped provider, never by a tool. */
export interface PushConfiguration {
  currentBranch?: string;
  configuredRefspecs?: readonly string[];
  pushDefault?: string;
  upstreamDestination?: string;
  /** Undefined means no tracking-remote relationship was established. */
  pushRemoteMatchesTracking?: boolean;
  mirror?: boolean;
  tagRefs?: readonly string[];
}

/** Concrete immutable-in-shape target; passed as an explicit refspec to Git. */
export interface PushPlanEntry {
  source: string;
  destination: string;
  force: boolean;
  delete: boolean;
}

/** A proved explicit empty selection is distinct from an invalid empty plan. */
type PrivatePushPlan =
  | { readonly kind: 'destinations'; readonly entries: PushPlanEntry[] }
  | { readonly kind: 'empty-explicit-tags' };

/** Resolve the closed provider intent without relaxing ordinary minimum counts. */
export function resolvePrivatePushPlan(
  options: PushPolicyInput,
  config: PushConfiguration,
): PrivatePushPlan {
  assertPushPolicy(options);
  if (
    options.tags === true &&
    options.branch === undefined &&
    options.remoteBranch === undefined &&
    !options.delete &&
    !config.mirror &&
    Array.isArray(config.tagRefs) &&
    config.tagRefs.length === 0
  )
    return { kind: 'empty-explicit-tags' };
  return { kind: 'destinations', entries: resolvePushPlan(options, config) };
}

function entry(spec: string): PushPlanEntry {
  const force = spec.startsWith('+');
  const value = force ? spec.slice(1) : spec;
  const fields = value.split(':');
  if (fields.length > 2 || !value)
    throw new Error('Ambiguous configured push refspec');
  const [src, dst] = fields;
  if (!src && !dst)
    throw new Error('Matching push refspec requires explicit destinations');
  const source = !src ? '' : src === 'HEAD' ? 'HEAD' : normalizePushRef(src);
  const destination = normalizePushRef(dst ?? src ?? '');
  return { source, destination, force, delete: !src };
}

/**
 * Resolve supported defaults to concrete targets once, then send only explicit
 * refspecs. Wildcard/matching/mirror modes fail closed instead of guessing impact.
 * The repository/destination capability is supplied separately by G1's provider.
 */
export function resolvePushPlan(
  options: PushPolicyInput,
  config: PushConfiguration,
): PushPlanEntry[] {
  assertPushPolicy(options);
  if (config.mirror)
    throw new Error('Mirror push is unsupported; select explicit destinations');
  const plans: PushPlanEntry[] = [];
  if (options.delete) {
    plans.push({
      source: '',
      destination: normalizePushRef(
        options.remoteBranch ?? options.branch ?? '',
      ),
      force: false,
      delete: true,
    });
  } else if (options.branch || options.remoteBranch) {
    const src = options.branch ?? 'HEAD';
    const dst =
      options.remoteBranch ?? (src === 'HEAD' ? config.currentBranch : src);
    if (!dst) throw new Error('Detached push requires an explicit destination');
    plans.push({
      source: src === 'HEAD' ? src : normalizePushRef(src),
      destination: normalizePushRef(dst),
      force: Boolean(options.force),
      delete: false,
    });
  } else if (!options.tags) {
    if ((config.configuredRefspecs?.length ?? 0) > 256)
      throw new Error('Push destination count exceeds the supported limit');
    if (config.configuredRefspecs?.length)
      plans.push(...config.configuredRefspecs.map(entry));
    else {
      if (!config.currentBranch)
        throw new Error('Detached push requires an explicit destination');
      const current = normalizePushRef(config.currentBranch);
      const mode = config.pushDefault ?? 'simple';
      if (
        mode === 'current' ||
        (mode === 'simple' && config.pushRemoteMatchesTracking === false)
      )
        plans.push({
          source: current,
          destination: current,
          force: false,
          delete: false,
        });
      else if (
        mode === 'upstream' ||
        mode === 'tracking' ||
        mode === 'simple'
      ) {
        if (!config.upstreamDestination)
          throw new Error(
            'Push requires an explicit destination or configured upstream',
          );
        const destination = normalizePushRef(config.upstreamDestination);
        if (mode === 'simple' && destination !== current)
          throw new Error(
            'Simple push upstream differs; select an explicit destination',
          );
        plans.push({
          source: current,
          destination,
          force: false,
          delete: false,
        });
      } else throw new Error('Push default requires explicit destinations');
    }
  }
  if (options.tags) {
    for (const tag of config.tagRefs ?? []) {
      const ref = normalizePushRef(tag);
      if (!ref.startsWith('refs/tags/'))
        throw new Error('Invalid enumerated tag ref');
      plans.push({
        source: ref,
        destination: ref,
        force: Boolean(options.force),
        delete: false,
      });
    }
  }
  if (plans.length === 0 || plans.length > 256)
    throw new Error('Push requires between 1 and 256 concrete destinations');
  const seen = new Set<string>();
  for (const plan of plans) {
    if (seen.has(plan.destination))
      throw new Error('Duplicate push destination');
    seen.add(plan.destination);
    assertPushPolicy({
      force: plan.force || Boolean(options.force),
      forceWithLease: Boolean(options.forceWithLease),
      delete: plan.delete,
      ...(options.confirmed === undefined
        ? {}
        : { confirmed: options.confirmed }),
      ...(plan.delete ? { remoteBranch: plan.destination } : {}),
    });
    if (options.force) plan.force = true;
  }
  return plans;
}
