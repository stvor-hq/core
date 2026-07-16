declare module 'bun:sqlite' {
  export interface RunResult {
    changes: number
    lastInsertRowid: number | bigint
  }
  export class Statement<T = unknown> {
    get(...params: unknown[]): T | null
    all(...params: unknown[]): T[]
    run(...params: unknown[]): RunResult
  }
  export class Database {
    constructor(filename?: string, options?: { create?: boolean; readwrite?: boolean; strict?: boolean })
    query<T = unknown>(sql: string): Statement<T>
    prepare<T = unknown>(sql: string): Statement<T>
    run(sql: string, ...params: unknown[]): RunResult
    exec(sql: string): void
    close(): void
  }
}
