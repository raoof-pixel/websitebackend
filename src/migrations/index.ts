import * as migration_20261023_141538_initial from './20261023_141538_initial';
import * as migration_20261023_190032_schema_update from './20261023_190032_schema_update';

export const migrations = [
  {
    up: migration_20261023_141538_initial.up,
    down: migration_20261023_141538_initial.down,
    name: '20261023_141538_initial',
  },
  {
    up: migration_20261023_190032_schema_update.up,
    down: migration_20261023_190032_schema_update.down,
    name: '20261023_190032_schema_update'
  },
];
