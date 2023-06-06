# bugslife_java

## Getting Started

### Installation

```bash
git clone
```

### Local Mysql connection

|          | Value     | memo        |
| -------- | --------- | ----------- |
| URL      | localhost |             |
| port     | 3306      |             |
| User     | root      |             |
| Password |           | no password |
| Scheme   | bugslife  |             |

### Create DATABASE in MySQL Workbench

```sql
CREATE DATABASE `bugslife`;
```

### Usage

```bash
cd bugslife_java
mvn clean install
mvn spring-boot:run
```

### Prerequisites

- Java 17
- Mysql 8.0

### Installing

- Install [MySQL](https://dev.mysql.com/downloads/mysql/)
- Install [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)
- Install [Java](https://www.oracle.com/java/technologies/javase-downloads.html)
- Install [Maven](https://maven.apache.org/download.cgi)

## Running the tests

```bash
mvn -B package --file pom.xml
```

## Docs

- [Code rule](./docs/code_rule.md)
- [Index](./docs/index.md)
- [User](./docs/users.md)
- [App](./docs/apps.md)
- [Campaign](./docs/campaigns.md)
- [Category](./docs/categories.md)
- [Company](./docs/companies.md)
- [Shop](./docs/shops.md)
- [Product](./docs/products.md)
- [Order](./docs/orders.md)
