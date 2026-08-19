// Package mikrotik talks to a RouterOS device's firewall address-lists.
package mikrotik

import (
	"context"
	"fmt"
	"strings"
)

// ManagedComment is the marker written on every entry this bouncer creates.
//
// It is what makes the reconciler safe to run against a live router: entries
// without this comment were put there by the operator and are never touched,
// and entries with it are ours to add, remove and de-duplicate at will.
const ManagedComment = "cs-routeros-sync"

// Family selects which RouterOS table an address-list lives in.
//
// This is not cosmetic: IPv4 and IPv6 address-lists are separate tables with
// separate .id spaces. Sending an IPv6 address to the IPv4 table makes
// RouterOS try to read it as a hostname and reject it with "is not a valid
// dns name".
type Family string

const (
	V4 Family = "v4"
	V6 Family = "v6"
)

// Path returns the API path for this family's address-list table.
func (f Family) Path() string {
	if f == V6 {
		return "/ipv6/firewall/address-list"
	}
	return "/ip/firewall/address-list"
}

// Entry is one row of a RouterOS firewall address-list.
type Entry struct {
	ID      string // RouterOS internal .id, empty for entries we have not created yet
	List    string
	Address string
	Comment string
	Timeout string
}

// Managed reports whether this entry is one of ours.
func (e Entry) Managed() bool {
	return e.Comment == ManagedComment || strings.HasPrefix(e.Comment, ManagedComment+";")
}

// Client is the subset of RouterOS we need. The reconciler depends on this
// interface rather than on a live device, so its logic is testable offline.
type Client interface {
	// List returns every entry currently in the named address-list.
	List(ctx context.Context, fam Family, list string) ([]Entry, error)

	// Add creates an entry and returns its new RouterOS .id.
	Add(ctx context.Context, fam Family, e Entry) (string, error)

	// Remove deletes entries by RouterOS .id. The ids are only meaningful
	// within their own family's table.
	Remove(ctx context.Context, fam Family, ids []string) error

	// Close releases the connection.
	Close() error
}

// quote escapes a value for use in a RouterOS API word.
//
// Address-list values are addresses and fixed comments rather than free text,
// but an "=key=value" word is terminated by the API framing, not by the shell,
// so a value containing "=" would still be misread. Reject those outright
// instead of silently sending something the router will interpret differently.
func attr(key, value string) (string, error) {
	if err := checkValue(key, value); err != nil {
		return "", err
	}
	return "=" + key + "=" + value, nil
}

// query builds a "?key=value" filter word, which RouterOS evaluates on the
// device rather than shipping the whole table back to us.
func query(key, value string) (string, error) {
	if err := checkValue(key, value); err != nil {
		return "", err
	}
	return "?" + key + "=" + value, nil
}

func checkValue(key, value string) error {
	if strings.ContainsAny(value, "\x00\n\r") {
		return fmt.Errorf("illegal character in %s=%q", key, value)
	}
	return nil
}
