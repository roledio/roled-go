package roled

import (
	"net/url"
	"strconv"
)

// Pagination represents pagination metadata returned by Roled list endpoints.
type Pagination struct {
	PageNum   int `json:"page_num"`
	PageSize  int `json:"page_size"`
	TotalData int `json:"total_data"`
}

// TotalPages calculates and returns the total number of pages.
func (p Pagination) TotalPages() int {
	if p.PageSize <= 0 {
		return 0
	}
	pages := p.TotalData / p.PageSize
	if p.TotalData%p.PageSize > 0 {
		pages++
	}
	return pages
}

// HasNext returns true if there is a next page available.
func (p Pagination) HasNext() bool {
	return p.PageNum < p.TotalPages()
}

// HasPrev returns true if there is a previous page available.
func (p Pagination) HasPrev() bool {
	return p.PageNum > 1
}

// ListParams holds common query parameters for paginated list requests.
type ListParams struct {
	PageNum  int
	PageSize int
	SortBy   string
	SortDir  string
	Search   string
}

// ToValues serializes ListParams into url.Values.
func (p ListParams) ToValues() url.Values {
	v := url.Values{}
	if p.PageNum > 0 {
		v.Set("page_num", strconv.Itoa(p.PageNum))
	}
	if p.PageSize > 0 {
		v.Set("page_size", strconv.Itoa(p.PageSize))
	}
	if p.SortBy != "" {
		v.Set("sort_by", p.SortBy)
	}
	if p.SortDir != "" {
		v.Set("sort_dir", p.SortDir)
	}
	if p.Search != "" {
		v.Set("search", p.Search)
	}
	return v
}

// responseEnvelope represents the JSON envelope returned by Roled API endpoints.
type responseEnvelope[T any] struct {
	Success    bool        `json:"success"`
	Data       T           `json:"data"`
	Pagination *Pagination `json:"pagination,omitempty"`
	Error      *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// StringPtr returns a pointer to the passed string.
func StringPtr(v string) *string {
	return &v
}

// BoolPtr returns a pointer to the passed bool.
func BoolPtr(v bool) *bool {
	return &v
}

// IntPtr returns a pointer to the passed int.
func IntPtr(v int) *int {
	return &v
}
