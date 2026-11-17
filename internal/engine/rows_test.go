package engine

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/praxin/xinproof/internal/receipt"
)

func TestReceiptTables(t *testing.T) {
	got, total := ReceiptTables([]TableCount{
		{Qualified: "public.orders", Kind: 'r', Rows: 40000},
		{DB: "shop", Qualified: "public.customers", Kind: 'r', Rows: 7},
		{Qualified: "public.audit_log", Kind: 'r', Rows: 0},
		{Qualified: "orders", Rows: 3},
	})
	want := []receipt.Table{
		{Name: "orders", Rows: 3},
		{Name: "public.audit_log", Rows: 0},
		{Name: "public.orders", Rows: 40000},
		{Name: "shop:public.customers", Rows: 7},
	}
	if total != 4 || !reflect.DeepEqual(got, want) {
		t.Errorf("got %v (total %d), want %v", got, total, want)
	}
	if got, total := ReceiptTables(nil); got != nil || total != 0 {
		t.Errorf("nil counts: got %v, %d", got, total)
	}
}

func TestReceiptTablesCap(t *testing.T) {
	var counts []TableCount
	n := receipt.MaxTables + 37
	for i := n - 1; i >= 0; i-- { // reverse order: the cap must keep the first by name
		counts = append(counts, TableCount{Qualified: fmt.Sprintf("t%05d", i), Rows: int64(i)})
	}
	got, total := ReceiptTables(counts)
	if total != n || len(got) != receipt.MaxTables {
		t.Fatalf("got %d tables (total %d), want %d of %d", len(got), total, receipt.MaxTables, n)
	}
	if got[0].Name != "t00000" || got[len(got)-1].Name != fmt.Sprintf("t%05d", receipt.MaxTables-1) {
		t.Errorf("kept %s … %s", got[0].Name, got[len(got)-1].Name)
	}
}
