package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	pool *pgxpool.Pool
}

func NewVulnStore(pool *pgxpool.Pool) *Store {
	return &Store{
		pool: pool,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// UpdateVulnerabilities implements vulnstore.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// GetUpdateOperations implements vulnstore.Updater.
func (s *Store) GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error) {
	return getUpdateOperations(ctx, s.pool, updater...)
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) error {
	return deleteUpdateOperations(ctx, s.pool, id...)
}

// GetUpdateOperationDiff implements vulnstore.Updater.
func (s *Store) GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}
func (s *Store) GetUpdateDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}

func (s *Store) GetLatestUpdateRefs(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return getLatestRefs(ctx, s.pool)
}

// Get implements vulnstore.Vulnerability.
func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, nil
}
