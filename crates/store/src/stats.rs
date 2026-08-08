use crate::{Store, StoreError};

#[derive(Debug, Clone, PartialEq)]
pub struct TableStat {
    pub table_name: String,
    pub row_count: i64,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbStats {
    pub row_count: i64,
    pub storage_bytes: i64,
    pub tables: Vec<TableStat>,
}

/// (table, expression summing the byte length of every column in a row)
const TABLE_SIZES: [(&str, &str); 4] = [
    ("cpu_usage", "LENGTH(CAST(time AS TEXT)) + LENGTH(CAST(percent AS TEXT))"),
    (
        "memory_usage",
        "LENGTH(CAST(time AS TEXT)) + LENGTH(CAST(total AS TEXT)) + \
         LENGTH(CAST(available AS TEXT)) + LENGTH(CAST(used AS TEXT)) + \
         LENGTH(CAST(used_percent AS TEXT)) + LENGTH(CAST(free AS TEXT))",
    ),
    (
        "container_cpu_usage",
        "LENGTH(CAST(time AS TEXT)) + LENGTH(container_id) + LENGTH(CAST(percent AS TEXT))",
    ),
    (
        "container_memory_usage",
        "LENGTH(CAST(time AS TEXT)) + LENGTH(container_id) + LENGTH(CAST(total AS TEXT)) + \
         LENGTH(CAST(available AS TEXT)) + LENGTH(CAST(used AS TEXT)) + \
         LENGTH(CAST(used_percent AS TEXT)) + LENGTH(CAST(free AS TEXT))",
    ),
];

impl Store {
    pub fn db_stats(&self) -> Result<DbStats, StoreError> {
        self.with_conn(|c| {
            let page_count: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;

            let mut tables = Vec::with_capacity(TABLE_SIZES.len());
            let mut row_count = 0i64;
            for (name, size_expr) in TABLE_SIZES {
                let count: i64 =
                    c.query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |r| r.get(0))?;
                let size: i64 = c.query_row(
                    &format!("SELECT COALESCE(SUM({size_expr}), 0) FROM {name}"),
                    [],
                    |r| r.get(0),
                )?;
                row_count += count;
                tables.push(TableStat {
                    table_name: name.to_string(),
                    row_count: count,
                    size_bytes: size,
                });
            }

            Ok(DbStats { row_count, storage_bytes: page_count * page_size, tables })
        })
    }
}
