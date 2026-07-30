package borg

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danieltamas/fortified/internal/sshx"
)

// ArchiveStats is one archive's size/timing info, from `borg info
// --json <repo>::<archive>`.
type ArchiveStats struct {
	Name             string `json:"name"`
	Start            string `json:"start"`
	End              string `json:"end"`
	NFiles           int64  `json:"nfiles"`
	OriginalSize     int64  `json:"original_size"`
	CompressedSize   int64  `json:"compressed_size"`
	DeduplicatedSize int64  `json:"deduplicated_size"`
}

// RepoStats is the whole repo's size info, from `borg info --json
// <repo>` (no archive) — UniqueSize/UniqueCompressedSize are the
// actual space consumed on the Storage Box after deduplication across
// every archive, TotalSize/TotalCompressedSize are the sum of every
// archive's own size were they not deduplicated against each other.
type RepoStats struct {
	TotalSize            int64 `json:"total_size"`
	TotalCompressedSize  int64 `json:"total_compressed_size"`
	UniqueSize           int64 `json:"unique_size"`
	UniqueCompressedSize int64 `json:"unique_compressed_size"`
	TotalChunks          int64 `json:"total_chunks"`
	TotalUniqueChunks    int64 `json:"total_unique_chunks"`
}

// borgInfoJSON mirrors the fields `borg info --json` emits — verified
// live against a real local repo, not guessed. archives is empty when
// no archive is named in the repo argument (repo-level query); it has
// exactly one entry when an archive is named.
type borgInfoJSON struct {
	Archives []struct {
		Name  string `json:"name"`
		Start string `json:"start"`
		End   string `json:"end"`
		Stats struct {
			NFiles           int64 `json:"nfiles"`
			OriginalSize     int64 `json:"original_size"`
			CompressedSize   int64 `json:"compressed_size"`
			DeduplicatedSize int64 `json:"deduplicated_size"`
		} `json:"stats"`
	} `json:"archives"`
	Cache struct {
		Stats struct {
			TotalSize         int64 `json:"total_size"`
			TotalCSize        int64 `json:"total_csize"`
			UniqueSize        int64 `json:"unique_size"`
			UniqueCSize       int64 `json:"unique_csize"`
			TotalChunks       int64 `json:"total_chunks"`
			TotalUniqueChunks int64 `json:"total_unique_chunks"`
		} `json:"stats"`
	} `json:"cache"`
}

// ArchiveInfo returns one archive's size/timing stats.
func (b Backend) ArchiveInfo(ctx context.Context, repoPath string, archiveID ArchiveID, passphrase, identityPath string) (ArchiveStats, error) {
	target := fmt.Sprintf("%s::%s", repoPath, archiveID)
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "borg", []string{"info", "--json", target},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath), Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return ArchiveStats{}, fmt.Errorf("borg: info %s: %w", target, err)
	}

	var parsed borgInfoJSON
	if err := json.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		return ArchiveStats{}, fmt.Errorf("borg: parse info %s: %w", target, err)
	}
	if len(parsed.Archives) == 0 {
		return ArchiveStats{}, fmt.Errorf("borg: info %s returned no archive stats", target)
	}
	a := parsed.Archives[0]
	return ArchiveStats{
		Name: a.Name, Start: a.Start, End: a.End, NFiles: a.Stats.NFiles,
		OriginalSize: a.Stats.OriginalSize, CompressedSize: a.Stats.CompressedSize, DeduplicatedSize: a.Stats.DeduplicatedSize,
	}, nil
}

// archiveListItem is one line of `borg list --json-lines` output —
// verified live against a real repo, not guessed. type "-" is a
// regular file (whose size is meaningful); directories ("d") and
// other types report size 0.
type archiveListItem struct {
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// ArchivePathSize sums the uncompressed size of every regular file
// under path within archiveID — narrower than ArchiveInfo's
// whole-archive OriginalSize, used by verify's free-space preflight to
// size only the subset of the archive it actually restores (its own
// database dumps' workspace directory), not every other archive path
// (raw filesystem paths from config's own `archive:` list) that
// verify's own checks never touch.
func (b Backend) ArchivePathSize(ctx context.Context, repoPath string, archiveID ArchiveID, passphrase, identityPath, path string) (int64, error) {
	target := fmt.Sprintf("%s::%s", repoPath, archiveID)
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "borg", []string{"list", "--json-lines", target, path},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath), Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return 0, fmt.Errorf("borg: list %s %s: %w", target, path, err)
	}
	var total int64
	for _, line := range splitNonEmptyLines(result.Stdout) {
		var item archiveListItem
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return 0, fmt.Errorf("borg: parse list line for %s %s: %w", target, path, err)
		}
		if item.Type == "-" {
			total += item.Size
		}
	}
	return total, nil
}

// RepoInfo returns the whole repo's deduplicated size totals.
func (b Backend) RepoInfo(ctx context.Context, repoPath, passphrase, identityPath string) (RepoStats, error) {
	result, err := b.Runner.Run(ctx, sshx.ReadOnly, "borg", []string{"info", "--json", repoPath},
		sshx.RunOptions{Env: remoteRepoEnv(passphrase, identityPath), Timeout: sshx.LongRunningTimeout})
	if err != nil {
		return RepoStats{}, fmt.Errorf("borg: info %s: %w", repoPath, err)
	}

	var parsed borgInfoJSON
	if err := json.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		return RepoStats{}, fmt.Errorf("borg: parse info %s: %w", repoPath, err)
	}
	return RepoStats{
		TotalSize: parsed.Cache.Stats.TotalSize, TotalCompressedSize: parsed.Cache.Stats.TotalCSize,
		UniqueSize: parsed.Cache.Stats.UniqueSize, UniqueCompressedSize: parsed.Cache.Stats.UniqueCSize,
		TotalChunks: parsed.Cache.Stats.TotalChunks, TotalUniqueChunks: parsed.Cache.Stats.TotalUniqueChunks,
	}, nil
}
