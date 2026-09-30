/**
 * Source locator (0045 / plan KTD3): map a key path in a CI YAML file to its 1-based
 * source line, so a `fail` finding can cite exactly where attacker input lands.
 *
 * Positions come from the YAML parser (`parseDocument` + `LineCounter`), never from a
 * text search — identical step text in two jobs would otherwise resolve to the wrong
 * one. Every lookup returns `undefined` instead of throwing, so missing evidence
 * demotes a finding (R8) rather than crashing the run. Invalid YAML is reported by the
 * analyzer's own parse; here it simply yields no positions.
 */

import { isMap, isScalar, isSeq, LineCounter, parseDocument, type Node } from 'yaml';

export type KeyPath = (string | number)[];

export interface SourceLocator {
  /** Line of the key (map segment) or list item (numeric segment) at the end of `path`. */
  line(path: KeyPath): number | undefined;
  /**
   * Line of a GitHub Actions step field: `run`, `uses`, `with.<key>`, or the step's own
   * start line when `field` is omitted.
   */
  stepLine(jobId: string, stepIndex: number, field?: string): number | undefined;
}

export function locateSource(yamlText: string): SourceLocator {
  const counter = new LineCounter();
  const doc = parseDocument(yamlText, { lineCounter: counter });
  const valid = doc.errors.length === 0;
  const lineAt = (offset: number): number => counter.linePos(offset).line;

  function line(path: KeyPath): number | undefined {
    if (!valid || path.length === 0) {
      return undefined;
    }
    let node: unknown = doc.contents;
    let at: number | undefined;
    for (const segment of path) {
      if (typeof segment === 'number') {
        if (!isSeq(node)) {
          return undefined;
        }
        const item = node.items[segment] as Node | undefined;
        if (!item?.range) {
          return undefined;
        }
        at = lineAt(item.range[0]);
        node = item;
      } else {
        if (!isMap(node)) {
          return undefined;
        }
        const pair = node.items.find((p) => isScalar(p.key) && p.key.value === segment);
        const key = pair?.key as Node | undefined;
        if (!pair || !key?.range) {
          return undefined;
        }
        at = lineAt(key.range[0]);
        node = pair.value;
      }
    }
    return at;
  }

  function stepLine(jobId: string, stepIndex: number, field?: string): number | undefined {
    const step: KeyPath = ['jobs', jobId, 'steps', stepIndex];
    return field === undefined ? line(step) : line([...step, ...field.split('.')]);
  }

  return { line, stepLine };
}
