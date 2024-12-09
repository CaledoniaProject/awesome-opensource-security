# opensource-re-tools

A collection of database tools

## Collections

Uncategorized

* [delta-io/delta - An open-source storage framework that enables building a Lakehouse architecture with compute engines including Spark, PrestoDB, Flink, Trino, and Hive and APIs - 6.5K star](https://github.com/delta-io/delta)
* [sqlancer - Detecting Logic Bugs in DBMS - 不知道干啥的](https://github.com/sqlancer/sqlancer)
* [orginly/navicat-keygen - Navicat Premium 15 linux 安装与激活 ArchLinux](https://github.com/orginly/navicat-keygen)

MySQL

* [twindb/undrop-for-innodb - TwinDB data recovery toolkit for MySQL/InnoDB - 可以读取IBD文件，测试MySQL 8.X有效](https://github.com/twindb/undrop-for-innodb)
  * [Restore table from .frm and .ibd file - undrop使用起来很复杂，上面的仓库没有对应的说明](https://stackoverflow.com/questions/75090681/restore-table-from-frm-and-ibd-file)
* [rmb122/rogue_mysql_server - A rouge mysql server supports reading files from most mysql libraries of multiple programming languages](https://github.com/rmb122/rogue_mysql_server)
  * [jib1337/Rogue-MySQL-Server - Fake MySQL Server that attempts to steal files from clients](https://github.com/jib1337/Rogue-MySQL-Server)
  * [fnmsd/MySQL_Fake_Server - MySQL Fake Server use to help MySQL Client File Reading and JDBC Client Java Deserialize](https://github.com/fnmsd/MySQL_Fake_Server)
  * [BeichenDream/MysqlT - 伪造Mysql服务端,并利用Mysql逻辑漏洞来获取客户端的任意文件反击攻击者](https://github.com/BeichenDream/MysqlT)
  * [4ra1n/mysql-fake-server - MySQL Fake Server (纯Java实现，内置常见Java反序列化Payload，支持GUI版和命令行版，提供Dockerfile)](https://github.com/4ra1n/mysql-fake-server)
* [mysqludf - 各种 MySQL UDF](https://github.com/mysqludf)
* [sqlmapproject/udfhack - SQLMap UDF，支持 MySQL/PG + Linux/Windows；目前sqlmap自带的二进制免杀](https://github.com/sqlmapproject/udfhack)
* [co01cat/SqlmapXPlus - SqlmapXPlus 基于 Sqlmap，对经典的数据库漏洞利用工具进行二开！](https://github.com/co01cat/SqlmapXPlus)
* [cyrus-and/mysql-unsha1 - Authenticate against a MySQL server without knowing the cleartext password - 当获取了mysql hash却无法解密的时候，可以用这个嗅探工具获取sha1；之后可以PTH，也可以去破解](https://github.com/cyrus-and/mysql-unsha1)
* [codeplutos/MySQL-JDBC-Deserialization-Payload - MySQL客户端jdbc反序列化漏洞 - 包含一个 query rewrite 插件例子](https://github.com/codeplutos/MySQL-JDBC-Deserialization-Payload)
* [MariaDB Audit Plugin - 默认就带了，装一下就可以](https://mariadb.com/kb/en/mariadb-audit-plugin/)

SQLite

* [aramosf/recoversqlite - recover deleted information from sqlite file](https://github.com/aramosf/recoversqlite)

Postgres

* [djrobstep/migra - Like diff but for PostgreSQL schemas](https://github.com/djrobstep/migra)
* [mkopec3/postgres-pth - PostgreSQL Pass-The-Hash - 基于9.5版本改的，很老了](https://github.com/mkopec3/postgres-pth)
* [Dionach/pgexec - Script and resources to execute shell commands using access to a PostgreSQL service - lo_export写文件](https://github.com/Dionach/pgexec)
  * [SQL Injection Double Uppercut :: How to Achieve Remote Code Execution Against PostgreSQL](https://srcincite.io/blog/2020/06/26/sql-injection-double-uppercut-how-to-achieve-remote-code-execution-against-postgresql.html)

MSSQL

* [IamLeandrooooo/SQLServerLinkedServersPasswords - A Powershell Script that automates all the needed configurations in order to get the SQL Server Linked Server Passwords](https://github.com/IamLeandrooooo/SQLServerLinkedServersPasswords)
* [sqlcollaborative/dbachecks - a framework created by and for SQL Server pros who need to validate their environments](https://github.com/sqlcollaborative/dbachecks)
* https://github.com/Ignitetechnologies/MSSQL-Pentest-Cheatsheet
* [nccgroup/nccfsas - main/Tools/Squeak - Connect to an MSSQL instance (as DBA/SA) and execute shellcode via a .net DLL - 可以执行MSF的payload](https://github.com/nccgroup/nccfsas/tree/main/Tools/Squeak)
  * [nccgroup: MSSQL Lateral Movement](https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/)
* [aleenzz/MSSQL_SQL_BYPASS_WIKI - MSSQL注入提权,bypass的一些总结 - 2019停更](https://github.com/aleenzz/MSSQL_SQL_BYPASS_WIKI)
  * [evi1ox/MSSQL_BackDoor - 目的主要是摆脱MSSMS和 Navicat 调用执行 sp_cmdExec](https://github.com/evi1ox/MSSQL_BackDoor)
* [NetSPI/ESC - an interactive .NET SQL console client with enhanced SQL Server discovery, access, and data exfiltration features](https://github.com/NetSPI/ESC)
* [OpenDBDiff/OpenDBDiff - A database comparison tool for Microsoft SQL Server 2005+ that reports schema differences and creates a synchronization script](https://github.com/OpenDBDiff/OpenDBDiff)
* [NetSPI/SQLC2 - a PowerShell script for deploying and managing a command and control system that uses SQL Server as both the control server and the agent](https://github.com/NetSPI/SQLC2)
* [NetSPI/PowerUpSQL - A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
  * [mlcsec/SharpSQL - Simple C# implementation of PowerUpSQL](https://github.com/mlcsec/SharpSQL)
* [quentinhardy/msdat - Microsoft SQL Database Attacking Tool](https://github.com/quentinhardy/msdat)
* [EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit - 类似 xp_cmdshell 一样的后门扩展](https://github.com/EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit)
* [jas502n/mssql-command-tool - mssql 终端连接工具|命令执行](https://github.com/jas502n/mssql-command-tool)
* [blackarrowsec/mssqlproxy - a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse - 作者说不支持并发连接；读写文件用 sp_OACreate 实现的](https://github.com/blackarrowsec/mssqlproxy)
* [uknowsec/SharpSQLTools - 命令行版sqltools](https://github.com/uknowsec/SharpSQLTools)
  * [Ridter/MSSQL_CLR - 在 SharpSQLTools CLR的基础上进行了功能增加和修改](https://github.com/Ridter/MSSQL_CLR)

NoSQL

* [torque59/Nosql-Exploitation-Framework - A Python Framework For NoSQL Scanning and Exploitation](https://github.com/torque59/Nosql-Exploitation-Framework)
* [codingo/NoSQLMap - Automated NoSQL database enumeration and web application exploitation tool](https://github.com/codingo/NoSQLMap)
* [Charlie-belmer/nosqli - NoSql Injection CLI tool, for finding vulnerable websites using MongoDB](https://github.com/Charlie-belmer/nosqli)

Oracle

* [quentinhardy/odat - Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)

Firebase

* [Turr0n/firebase - Exploiting misconfigured firebase databases](https://github.com/Turr0n/firebase)

GraphQL

* [nikitastupin/clairvoyance - Obtain GraphQL API schema even if the introspection is disabled](https://github.com/nikitastupin/clairvoyance)
* [dolevf/graphw00f - graphw00f is GraphQL Server Engine Fingerprinting utility for software security professionals looking to learn more about what technology is behind a given GraphQL endpoint](https://github.com/dolevf/graphw00f)
* [assetnote/batchql - GraphQL security auditing script with a focus on performing batch GraphQL queries and mutations](https://github.com/assetnote/batchql)
* [dee-see/graphql-path-enum - Tool that lists the different ways of reaching a given type in a GraphQL schema](https://gitlab.com/dee-see/graphql-path-enum)
* [swisskyrepo/GraphQLmap - a scripting engine to interact with a graphql endpoint for pentesting purposes](https://github.com/swisskyrepo/GraphQLmap)
* [GraphQL Voyager](https://apis.guru/graphql-voyager/)

## Resources

Uncategorized

* [Postgresql 渗透总结](https://tttang.com/archive/1547/)
* [mssql 提权总结 - 介绍存储过程](https://tttang.com/archive/1545/)
* [深信服千里目安全实验室 - MSSQL数据库攻击实战指北 | 防守方攻略](https://mp.weixin.qq.com/s/uENvpPan7aVd7MbSoAT9Dg)
* [slideshare: Beyond xp_cmdshell: Owning the Empire through SQL Server - netspi 写的，主要讲解 PowerUpSQL 相关的技巧](https://www.slideshare.net/nullbind/beyond-xpcmdshell-owning-the-empire-through-sql-server)
* [Using SQL Injection to perform SSRF/XSPA attacks - 讲解各种数据库的内置HTTP、TCP请求函数](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)
* [CVE-2020-25695 Privilege Escalation in Postgresql](https://staaldraad.github.io/post/2020-12-15-cve-2020-25695-postgresql-privesc/)

Data format

* [mtf - a Microsoft Tape Format reader](https://github.com/KyleBruene/mtf)
* [Microsoft Tape Format Specification 中文，2000年的文档](https://chenjianlong.gitbooks.io/microsoft-tape-format-specification/content/section5/01_common_blk_hdr.html)
  * [chenjianlong/mtf-in-chinese - Microsoft Tape Format Specification Version 1.00a - document rev. 1.8 in chinese](https://github.com/chenjianlong/mtf-in-chinese)
