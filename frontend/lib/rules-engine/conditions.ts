/**
 * Shared condition tree types used by the rules engine.
 *
 * These are imported by both the ConditionBuilder UI component and the
 * rules API client modules so the tree shape stays consistent across
 * all rule categories (notification routing, SLA, etc.).
 */

export type ConditionOp =
  | "eq"
  | "neq"
  | "in"
  | "nin"
  | "contains"
  | "not_contains"
  | "gt"
  | "gte"
  | "lt"
  | "lte"

export interface LeafCondition {
  field: string
  op: ConditionOp
  value: string | string[] | number | boolean
}

export interface AllCondition {
  all: Condition[]
}

export interface AnyCondition {
  any: Condition[]
}

export type Condition = LeafCondition | AllCondition | AnyCondition | Record<string, never>
