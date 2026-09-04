declare module 'sql.js' {
  export interface Database {
    run(sql: string, params?: unknown[]): void;
    exec(sql: string, params?: unknown[]): Array<{ columns: string[]; values: unknown[][] }>;
    export(): Uint8Array;
  }

  interface SqlJsStatic {
    Database: new (data?: Uint8Array) => Database;
  }

  const initSqlJs: (config?: unknown) => Promise<SqlJsStatic>;
  export default initSqlJs;
}
