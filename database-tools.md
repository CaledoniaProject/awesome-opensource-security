# opensource-re-tools

A collection of database tools

## Collections

Uncategorized

* [sqlmapproject/udfhack - Database takeover UDF repository](https://github.com/sqlmapproject/udfhack)
* [sqlancer - Detecting Logic Bugs in DBMS - 不知道干啥的](https://github.com/sqlancer/sqlancer)

MySQL

* [mysqludf - 各种 MySQL UDF](https://github.com/mysqludf)
* [sqlmapproject/udfhack - SQLMap UDF，支持 MySQL/PG + Linux/Windows；目前sqlmap自带的二进制免杀](https://github.com/sqlmapproject/udfhack)
* [cyrus-and/mysql-unsha1 - Authenticate against a MySQL server without knowing the cleartext password - 当获取了mysql hash却无法解密的时候，可以用这个嗅探工具获取sha1；之后可以PTH，也可以去破解](https://github.com/cyrus-and/mysql-unsha1)
* [codeplutos/MySQL-JDBC-Deserialization-Payload - MySQL客户端jdbc反序列化漏洞 - 包含一个 query rewrite 插件例子](https://github.com/codeplutos/MySQL-JDBC-Deserialization-Payload)

SQLite

* [aramosf/recoversqlite - recover deleted information from sqlite file](https://github.com/aramosf/recoversqlite)

PG

* [djrobstep/migra - Like diff but for PostgreSQL schemas](https://github.com/djrobstep/migra)
* [mkopec3/postgres-pth - PostgreSQL Pass-The-Hash - 基于9.5版本改的，很老了](https://github.com/mkopec3/postgres-pth)
* [Dionach/pgexec - Script and resources to execute shell commands using access to a PostgreSQL service](https://github.com/Dionach/pgexec)
  * [SQL Injection Double Uppercut :: How to Achieve Remote Code Execution Against PostgreSQL](https://srcincite.io/blog/2020/06/26/sql-injection-double-uppercut-how-to-achieve-remote-code-execution-against-postgresql.html)

MSSQL

* [EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit - CLR组件，包含多个RAT功能](https://github.com/EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit)
  * [evi1ox/MSSQL_BackDoor - 目的主要是摆脱MSSMS和 Navicat 调用执行 sp_cmdExec](https://github.com/evi1ox/MSSQL_BackDoor)
* [NetSPI/ESC - an interactive .NET SQL console client with enhanced SQL Server discovery, access, and data exfiltration features](https://github.com/NetSPI/ESC)
* [OpenDBDiff/OpenDBDiff - A database comparison tool for Microsoft SQL Server 2005+ that reports schema differences and creates a synchronization script](https://github.com/OpenDBDiff/OpenDBDiff)
* [NetSPI/SQLC2 - a PowerShell script for deploying and managing a command and control system that uses SQL Server as both the control server and the agent](https://github.com/NetSPI/SQLC2)
* [NetSPI/PowerUpSQL - A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
* [quentinhardy/msdat - Microsoft SQL Database Attacking Tool](https://github.com/quentinhardy/msdat)
* [EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit - 类似 xp_cmdshell 一样的后门扩展](https://github.com/EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit)
* [jas502n/mssql-command-tool - mssql 终端连接工具|命令执行](https://github.com/jas502n/mssql-command-tool)
* [blackarrowsec/mssqlproxy - a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse - 作者说不支持并发连接；读写文件用 sp_OACreate 实现的](https://github.com/blackarrowsec/mssqlproxy)
* [uknowsec/SharpSQLTools - 命令行版sqltools](https://github.com/uknowsec/SharpSQLTools)

NOSQL

* [torque59/Nosql-Exploitation-Framework - A Python Framework For NoSQL Scanning and Exploitation](https://github.com/torque59/Nosql-Exploitation-Framework)
* [codingo/NoSQLMap - Automated NoSQL database enumeration and web application exploitation tool](https://github.com/codingo/NoSQLMap)

Oracle

* [quentinhardy/odat - Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)

Firebase

* [Turr0n/firebase - Exploiting misconfigured firebase databases](https://github.com/Turr0n/firebase)

## References

* [slideshare: Beyond xp_cmdshell: Owning the Empire through SQL Server - netspi 写的，主要讲解 PowerUpSQL 相关的技巧](https://www.slideshare.net/nullbind/beyond-xpcmdshell-owning-the-empire-through-sql-server)
* [Using SQL Injection to perform SSRF/XSPA attacks - 讲解各种数据库的内置HTTP、TCP请求函数](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)



