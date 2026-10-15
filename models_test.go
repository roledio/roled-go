package roled

import (
	"testing"
)

func TestPagination(t *testing.T) {
	p := Pagination{
		PageNum:   1,
		PageSize:  10,
		TotalData: 25,
	}

	if p.TotalPages() != 3 {
		t.Errorf("expected 3 total pages, got %d", p.TotalPages())
	}
	if !p.HasNext() {
		t.Errorf("expected HasNext to be true on page 1")
	}
	if p.HasPrev() {
		t.Errorf("expected HasPrev to be false on page 1")
	}

	p2 := Pagination{
		PageNum:   3,
		PageSize:  10,
		TotalData: 25,
	}
	if p2.HasNext() {
		t.Errorf("expected HasNext to be false on last page")
	}
	if !p2.HasPrev() {
		t.Errorf("expected HasPrev to be true on page 3")
	}

	pZero := Pagination{
		PageNum:   1,
		PageSize:  0,
		TotalData: 0,
	}
	if pZero.TotalPages() != 0 {
		t.Errorf("expected 0 total pages for zero page size")
	}
}

func TestListParams_ToValues(t *testing.T) {
	lp := ListParams{
		PageNum:  2,
		PageSize: 15,
		SortBy:   "name",
		SortDir:  "asc",
		Search:   "test",
	}

	vals := lp.ToValues()
	if vals.Get("page_num") != "2" {
		t.Errorf("expected page_num=2, got %s", vals.Get("page_num"))
	}
	if vals.Get("page_size") != "15" {
		t.Errorf("expected page_size=15, got %s", vals.Get("page_size"))
	}
	if vals.Get("sort_by") != "name" {
		t.Errorf("expected sort_by=name, got %s", vals.Get("sort_by"))
	}
	if vals.Get("sort_dir") != "asc" {
		t.Errorf("expected sort_dir=asc, got %s", vals.Get("sort_dir"))
	}
	if vals.Get("search") != "test" {
		t.Errorf("expected search=test, got %s", vals.Get("search"))
	}
}

func TestPointerHelpers(t *testing.T) {
	s := StringPtr("hello")
	if s == nil || *s != "hello" {
		t.Errorf("expected 'hello', got %v", s)
	}

	b := BoolPtr(true)
	if b == nil || !*b {
		t.Errorf("expected true, got %v", b)
	}

	i := IntPtr(42)
	if i == nil || *i != 42 {
		t.Errorf("expected 42, got %v", i)
	}
}
