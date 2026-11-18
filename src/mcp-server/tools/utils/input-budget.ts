/**
 * @fileoverview Apply domain budgets to tool schemas without replacing their validators.
 * @module mcp-server/tools/utils/input-budget
 */
import { z } from 'zod';
import { type ToolInputLimits } from '../../transports/http/httpSecurity.js';

/** Clone input-only schema nodes, preserving descriptions, checks and default values. */
function boundSchema(schema: z.ZodType, limits: ToolInputLimits): z.ZodType {
  let bounded: z.ZodType = schema;
  if (schema instanceof z.ZodArray) {
    bounded = schema
      .clone({
        ...schema.def,
        element: boundSchema(schema.element as z.ZodType, limits),
      })
      .max(limits.maxArrayLength);
  } else if (schema instanceof z.ZodString) {
    bounded = schema
      .max(limits.maxStringBytes)
      .refine(
        (value) =>
          new TextEncoder().encode(value).byteLength <= limits.maxStringBytes,
        'String byte limit exceeded.',
      );
  } else if (schema instanceof z.ZodObject) {
    const shape = Object.fromEntries(
      Object.entries(schema.shape).map(([key, value]) => [
        key,
        boundSchema(value as z.ZodType, limits),
      ]),
    );
    bounded = schema.clone({ ...schema.def, shape });
  } else if (
    schema instanceof z.ZodOptional ||
    schema instanceof z.ZodNullable ||
    schema instanceof z.ZodDefault ||
    schema instanceof z.ZodReadonly ||
    schema instanceof z.ZodNonOptional ||
    schema instanceof z.ZodPrefault
  ) {
    bounded = z.clone(schema, {
      ...schema.def,
      innerType: boundSchema(schema.def.innerType as z.ZodType, limits),
    });
  } else if (schema instanceof z.ZodPipe) {
    bounded = schema.clone({
      ...schema.def,
      in: boundSchema(schema.in as z.ZodType, limits),
    });
  } else if (schema instanceof z.ZodUnion) {
    bounded = schema.clone({
      ...schema.def,
      options: schema.options.map((option) =>
        boundSchema(option as z.ZodType, limits),
      ),
    });
  } else if (schema instanceof z.ZodRecord) {
    bounded = schema
      .clone({
        ...schema.def,
        valueType: boundSchema(schema.valueType as z.ZodType, limits),
      })
      .refine(
        (value) => Object.keys(value).length <= limits.maxRecordKeys,
        'Record member limit exceeded.',
      );
  }
  if (schema.description) bounded = bounded.describe(schema.description);
  return bounded;
}

/** Preserve the input/output contract while adding strictly narrower domain budgets. */
export function boundToolInputSchema<T extends z.ZodType>(
  schema: T,
  limits: ToolInputLimits,
): T {
  return boundSchema(schema, limits) as T;
}
