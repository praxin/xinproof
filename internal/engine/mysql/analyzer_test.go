package mysql

import (
	"reflect"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

const goodDump = "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n" +
	"--\n-- Host: localhost    Database: shop\n" +
	"-- Server version\t8.0.36\n\n" +
	"/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n" +
	"DROP TABLE IF EXISTS `customers`;\n" +
	"CREATE TABLE `customers` (\n  `id` int NOT NULL,\n  `name` text\n) ENGINE=InnoDB;\n" +
	"LOCK TABLES `customers` WRITE;\n" +
	"INSERT INTO `customers` VALUES (1,'ann'),(2,'bob (the \\'builder\\'), jr.'),(3,'semi;colon'),(4,'back\\\\slash'),(5,NULL);\n" +
	"INSERT INTO `customers` VALUES (6,'two\\nlines'),(7,'\"dq\" (x)');\n" +
	"UNLOCK TABLES;\n" +
	"CREATE TABLE `order items` (\n  `id` int\n);\n" +
	"INSERT INTO `order items` (`id`) VALUES (1),(2);\n" +
	"INSERT IGNORE INTO `order items` VALUES (3);\n" +
	"CREATE TABLE `empty` (`id` int);\n" +
	"/*!50001 CREATE VIEW `v` AS SELECT 1 AS `a`*/;\n" +
	"/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n\n" +
	"-- Dump completed on 2026-11-17 10:00:00\n"

func feed(s string, chunk int) *Analyzer {
	a := NewAnalyzer()
	for len(s) > 0 {
		n := min(chunk, len(s))
		a.Write([]byte(s[:n]))
		s = s[n:]
	}
	return a
}

func TestAnalyzer(t *testing.T) {
	insertCut := strings.Index(goodDump, "(3,'semi")
	tests := []struct {
		name   string
		in     string
		status string
		detail string
		rows   map[string]int64
	}{
		{name: "complete", in: goodDump, status: receipt.CheckPass, detail: "Dump completed",
			rows: map[string]int64{engine.TableKey("", "customers"): 7, engine.TableKey("", "order items"): 3, engine.TableKey("", "empty"): 0}},
		{name: "cut inside an INSERT", in: goodDump[:insertCut], status: receipt.CheckFail, detail: "inside an INSERT into customers"},
		{name: "cut inside a quoted string", in: goodDump[:strings.Index(goodDump, "builder")], status: receipt.CheckFail, detail: "inside an INSERT"},
		{name: "cut before the trailer", in: goodDump[:strings.Index(goodDump, "-- Dump completed")], status: receipt.CheckFail, detail: "'-- Dump completed' line is missing"},
		{name: "skip-comments dump", in: "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\nCREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1);\n/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n",
			status: receipt.CheckPass, detail: "session-restore", rows: map[string]int64{engine.TableKey("", "t"): 1}},
		{name: "compact dump", in: "CREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1),(2);\n", status: receipt.CheckPass, detail: "can't be ruled out"},
		{name: "compact dump cut mid-statement", in: "CREATE TABLE `t` (`id` int);\nCREATE TABLE `u` (", status: receipt.CheckFail, detail: "mid-statement"},
		{name: "multi-database dump", in: "-- MySQL dump 10.13  Distrib 8.4.3, for Linux\nUSE `shop`;\nCREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1),(2);\nUSE `crm`;\nCREATE TABLE `t` (`id` int);\nINSERT INTO `shop`.`t` VALUES (3);\nINSERT INTO `t` VALUES (9);\n-- Dump completed on 2026-11-17\n",
			status: receipt.CheckPass, rows: map[string]int64{engine.TableKey("shop", "t"): 3, engine.TableKey("crm", "t"): 1}},
	}
	for _, tt := range tests {
		for _, chunk := range []int{1, 5, 64, 1 << 20} {
			a := feed(tt.in, chunk)
			c := a.Finish()
			if len(c) != 1 || c[0].Status != tt.status || !strings.Contains(c[0].Detail, tt.detail) {
				t.Errorf("%s (chunk %d): %+v, want %s containing %q", tt.name, chunk, c, tt.status, tt.detail)
			}
			if tt.rows != nil && !reflect.DeepEqual(a.Rows, tt.rows) {
				t.Errorf("%s (chunk %d): rows %v, want %v", tt.name, chunk, a.Rows, tt.rows)
			}
		}
	}
	if a := feed(goodDump, 7); a.Tables != 3 {
		t.Errorf("tables = %d, want 3", a.Tables)
	}
}

func TestHugeInsertLine(t *testing.T) {
	var b strings.Builder
	b.WriteString("-- MySQL dump 10.13  Distrib 8.0.36, for Linux\nCREATE TABLE `big` (`id` int, `s` text);\nINSERT INTO `big` VALUES ")
	const n = 300_000 // a ~9 MB line, far above the line buffer
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(1,'x),(y')")
	}
	b.WriteString(";\n-- Dump completed\n")
	a := feed(b.String(), 32<<10)
	if got := a.Rows[engine.TableKey("", "big")]; got != n {
		t.Errorf("rows = %d, want %d", got, n)
	}
	if c := a.Finish(); c[0].Status != receipt.CheckPass {
		t.Errorf("finish = %+v", c)
	}
}

func TestImageFor(t *testing.T) {
	e := &Engine{}
	tests := map[[3]string]string{
		{"mysql", "8.0.36", "8.0.36"}:                           "mysql:8.0",
		{"mysql", "8.4.3", "8.0.40"}:                            "mysql:8.0",
		{"mysql", "9.1.0", ""}:                                  "mysql:9.1",
		{"mysql", "", ""}:                                       "mysql:" + DefaultMySQL,
		{"mariadb", "11.4.2-MariaDB", "11.4.2-MariaDB-ubu2404"}: "mariadb:11.4",
		{"mariadb", "10.11.6-MariaDB", ""}:                      "mariadb:10.11",
		{"mariadb", "", ""}:                                     "mariadb:" + DefaultMariaDB,
	}
	for in, want := range tests {
		if got := e.ImageFor(in[0], in[1], in[2]); got != want {
			t.Errorf("ImageFor(%q) = %s, want %s", in, got, want)
		}
	}
}
