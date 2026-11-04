/**
 * @fileoverview Defines local OpenTelemetry semantic convention constants to ensure
 * stability and avoid dependency conflicts with different versions of
 * `@opentelemetry/semantic-conventions`.
 * @module src/utils/telemetry/semconv
 */

/**
 * The method or function name, or equivalent (usually rightmost part of the code unit's name).
 */
export const ATTR_CODE_FUNCTION = 'code.function';

/**
 * The "namespace" within which `code.function` is defined.
 * Usually the qualified class or module name, etc.
 */
export const ATTR_CODE_NAMESPACE = 'code.namespace';

/**
 * MCP tool execution attribute keys (local stability wrappers).
 */
export const ATTR_MCP_TOOL_INPUT_BYTES = 'mcp.tool.input_bytes';
export const ATTR_MCP_TOOL_OUTPUT_BYTES = 'mcp.tool.output_bytes';
/** True only when byte size was measured without unbounded serialization. */
export const ATTR_MCP_TOOL_INPUT_SIZE_KNOWN = 'mcp.tool.input_size_known';
/** Successful result metadata, not the JSON-RPC envelope/error response size. */
export const ATTR_MCP_TOOL_OUTPUT_SIZE_KNOWN = 'mcp.tool.output_size_known';
export const ATTR_MCP_TOOL_DURATION_MS = 'mcp.tool.duration_ms';
export const ATTR_MCP_TOOL_SUCCESS = 'mcp.tool.success';
export const ATTR_MCP_TOOL_ERROR_CODE = 'mcp.tool.error_code';

export const ATTR_MCP_TOOL_MEMORY_RSS_BEFORE =
  'mcp.tool.memory_rss_bytes.before';
export const ATTR_MCP_TOOL_MEMORY_RSS_AFTER = 'mcp.tool.memory_rss_bytes.after';
export const ATTR_MCP_TOOL_MEMORY_RSS_DELTA = 'mcp.tool.memory_rss_bytes.delta';

export const ATTR_MCP_TOOL_MEMORY_HEAP_USED_BEFORE =
  'mcp.tool.memory_heap_used_bytes.before';
export const ATTR_MCP_TOOL_MEMORY_HEAP_USED_AFTER =
  'mcp.tool.memory_heap_used_bytes.after';
export const ATTR_MCP_TOOL_MEMORY_HEAP_USED_DELTA =
  'mcp.tool.memory_heap_used_bytes.delta';
