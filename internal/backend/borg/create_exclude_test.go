package borg

import (
	"context"
	"reflect"
	"testing"

	"github.com/danieltamas/fortified/internal/sshx"
	"github.com/danieltamas/fortified/internal/sshx/sshxtest"
)

func TestCreateArchiveExcludeArgvAcceptance(t *testing.T) {
	fake := &sshxtest.FakeRunner{Responses: []sshxtest.Response{
		{Result: sshx.Result{Stdout: "Avail\n999999999999"}}, // df
		{}, // mkdir
		{}, // manifest
		{}, // create
		{}, // cleanup
	}}
	b := Backend{Runner: fake}
	excludes := []string{"/home/docker/psql/data", "/home/docker/psql/cache with spaces"}
	if _, _, err := b.CreateArchive(context.Background(), "/repo/x", "pw", "/identity-key", "/work/x", "acceptance",
		nil, nil, []string{"/home/docker/psql"}, excludes, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"create", "--progress", "--stats", "--exclude", "pp:/home/docker/psql/data",
		"--exclude", "pp:/home/docker/psql/cache with spaces", "/repo/x::acceptance", "/work/x", "/home/docker/psql"}
	for _, call := range fake.Calls {
		if call.Cmd == "borg" && len(call.Args) > 0 && call.Args[0] == "create" {
			if !reflect.DeepEqual(call.Args, want) {
				t.Fatalf("create argv = %q, want %q (prefix excludes before ARCHIVE)", call.Args, want)
			}
			return
		}
	}
	t.Fatal("no borg create call")
}
