/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as agentScans from "../agentScans.js";
import type * as connections from "../connections.js";
import type * as drive from "../drive.js";
import type * as github from "../github.js";
import type * as gmail from "../gmail.js";
import type * as outlook from "../outlook.js";
import type * as pipeline from "../pipeline.js";
import type * as scanResults from "../scanResults.js";
import type * as slack from "../slack.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  agentScans: typeof agentScans;
  connections: typeof connections;
  drive: typeof drive;
  github: typeof github;
  gmail: typeof gmail;
  outlook: typeof outlook;
  pipeline: typeof pipeline;
  scanResults: typeof scanResults;
  slack: typeof slack;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
